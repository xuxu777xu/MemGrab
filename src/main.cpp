// Modern C++ refactored version
// QBDI + Frida Gum memory trace for Android JNI

#include "../gum/frida-gum.h"
#include "../qbdi/include/QBDI.h"
#include "../qbdi/include/QBDI/Memory.h"

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// ============================================================================
// NAMESPACE: memtrace
// ============================================================================
namespace memtrace {

// ----------------------------------------------------------------------------
// CONFIG
// ----------------------------------------------------------------------------
namespace config {
constexpr std::string_view kLogTag = "memtrace";
constexpr std::string_view kLogPath =
    "/data/data/com.example.exampleapp/files/memtrace.log";
constexpr std::string_view kTargetClass =
    "com.exampleapp.safeboxlib.CryptoHelper";
constexpr std::string_view kTargetMethod = "localAESWork";
constexpr std::string_view kTargetSig = "([BI[B)[B";
constexpr uint32_t kQBDIStackSize = 0x20000;
constexpr uint32_t kResolverTimeoutSec = 300;
}  // namespace config

// ----------------------------------------------------------------------------
// LOGGING (template functions instead of macros)
// ----------------------------------------------------------------------------
namespace log {
inline void info(const char* msg) {
    __android_log_print(ANDROID_LOG_INFO, config::kLogTag.data(), "%s", msg);
}

template <typename... Args>
inline void info(const char* fmt, Args... args) {
    __android_log_print(ANDROID_LOG_INFO, config::kLogTag.data(), fmt, args...);
}

inline void error(const char* msg) {
    __android_log_print(ANDROID_LOG_ERROR, config::kLogTag.data(), "%s", msg);
}

template <typename... Args>
inline void error(const char* fmt, Args... args) {
    __android_log_print(ANDROID_LOG_ERROR, config::kLogTag.data(), fmt, args...);
}
}  // namespace log

// ----------------------------------------------------------------------------
// FORMAT UTILITIES
// ----------------------------------------------------------------------------
namespace fmt {
inline void appendf(std::string& out, const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(nullptr, 0, format, ap);
    va_end(ap);
    if (n <= 0) return;

    size_t old_size = out.size();
    out.resize(old_size + static_cast<size_t>(n) + 1);
    va_start(ap, format);
    vsnprintf(out.data() + old_size, static_cast<size_t>(n) + 1, format, ap);
    va_end(ap);
    out.pop_back();
}
}  // namespace fmt

// ----------------------------------------------------------------------------
// RAII GUARDS
// ----------------------------------------------------------------------------

// GObject smart pointer with custom deleter
struct GObjectDeleter {
    void operator()(gpointer p) const noexcept {
        if (p) g_object_unref(p);
    }
};

template <typename T>
using GObjectPtr = std::unique_ptr<T, GObjectDeleter>;

template <typename T>
GObjectPtr<T> make_gobject(T* raw) {
    return GObjectPtr<T>(raw);
}

// JNI LocalFrame RAII guard
class JniLocalFrame {
public:
    explicit JniLocalFrame(JNIEnv* env, jint capacity = 16)
        : env_(env), ok_(env && env->PushLocalFrame(capacity) >= 0) {}

    ~JniLocalFrame() {
        if (ok_) env_->PopLocalFrame(nullptr);
    }

    JniLocalFrame(const JniLocalFrame&) = delete;
    JniLocalFrame& operator=(const JniLocalFrame&) = delete;

    explicit operator bool() const noexcept { return ok_; }

    template <typename T>
    T pop(T result) {
        if (!ok_) return result;
        ok_ = false;
        return static_cast<T>(env_->PopLocalFrame(result));
    }

private:
    JNIEnv* env_;
    bool ok_;
};

// Recursion guard for thread-local flag
class RecursionGuard {
public:
    explicit RecursionGuard(bool& flag) noexcept
        : flag_(flag), was_set_(flag) {
        flag_ = true;
    }

    ~RecursionGuard() noexcept { flag_ = was_set_; }

    RecursionGuard(const RecursionGuard&) = delete;
    RecursionGuard& operator=(const RecursionGuard&) = delete;

    bool was_recursive() const noexcept { return was_set_; }

private:
    bool& flag_;
    bool was_set_;
};

// ----------------------------------------------------------------------------
// TYPE-SAFE HANDLES
// ----------------------------------------------------------------------------

// ART method handle (wraps jmethodID / ArtMethod*)
struct ArtMethodHandle {
    void* ptr = nullptr;

    ArtMethodHandle() noexcept = default;
    explicit ArtMethodHandle(void* p) noexcept : ptr(p) {}
    explicit ArtMethodHandle(jmethodID mid) noexcept
        : ptr(reinterpret_cast<void*>(mid)) {}

    explicit operator bool() const noexcept { return ptr != nullptr; }
    bool operator==(const ArtMethodHandle& o) const noexcept {
        return ptr == o.ptr;
    }
    bool operator!=(const ArtMethodHandle& o) const noexcept {
        return ptr != o.ptr;
    }
};

// Native entry point handle
struct NativeEntryHandle {
    void* ptr = nullptr;

    NativeEntryHandle() noexcept = default;
    explicit NativeEntryHandle(void* p) noexcept : ptr(p) {}

    explicit operator bool() const noexcept { return ptr != nullptr; }

    template <typename F>
    F as() const noexcept {
        return reinterpret_cast<F>(ptr);
    }
};

// Address conversion helpers
template <typename T>
constexpr QBDI::rword to_rword(T* p) noexcept {
    return reinterpret_cast<QBDI::rword>(p);
}

template <typename T>
constexpr T* from_rword(QBDI::rword r) noexcept {
    return reinterpret_cast<T*>(r);
}

// jint zero-extension to rword (avoid sign extension)
constexpr QBDI::rword jint_to_rword(jint v) noexcept {
    return static_cast<QBDI::rword>(static_cast<uint32_t>(v));
}

// ----------------------------------------------------------------------------
// GLOBAL STATE
// ----------------------------------------------------------------------------
namespace state {
std::mutex g_file_lock;
int g_log_fd = -1;
std::atomic<uint64_t> g_call_id{0};
std::atomic<ArtMethodHandle> g_target_art_method{};
std::atomic<NativeEntryHandle> g_target_native{};
}  // namespace state

// ----------------------------------------------------------------------------
// UTILITIES
// ----------------------------------------------------------------------------
inline pid_t gettid_fast() {
    return static_cast<pid_t>(syscall(__NR_gettid));
}

// ----------------------------------------------------------------------------
// FILE I/O
// ----------------------------------------------------------------------------
void append_to_file(const std::string& data) {
    std::lock_guard<std::mutex> lock(state::g_file_lock);
    if (state::g_log_fd < 0) {
        state::g_log_fd =
            open(config::kLogPath.data(), O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (state::g_log_fd < 0) {
            log::error("open(%s) failed: %s", config::kLogPath.data(),
                       std::strerror(errno));
            return;
        }
    }
    const char* p = data.data();
    size_t remaining = data.size();
    while (remaining > 0) {
        ssize_t w = write(state::g_log_fd, p, remaining);
        if (w < 0) {
            if (errno == EINTR) continue;
            log::error("write failed: %s", std::strerror(errno));
            close(state::g_log_fd);
            state::g_log_fd = -1;
            break;
        }
        if (w == 0) break;
        p += static_cast<size_t>(w);
        remaining -= static_cast<size_t>(w);
    }
}

// ----------------------------------------------------------------------------
// JNI UTILITIES
// ----------------------------------------------------------------------------
static JavaVM* get_created_jvm() {
    JavaVM* vms[1] = {nullptr};
    jsize n = 0;
    if (JNI_GetCreatedJavaVMs(vms, 1, &n) != JNI_OK || n <= 0) {
        return nullptr;
    }
    return vms[0];
}

static void clear_jni_exception(JNIEnv* env) {
    if (env && env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

static bool clear_jni_exception_and_log(JNIEnv* env, const char* stage) {
    if (!env || !env->ExceptionCheck()) return false;
    env->ExceptionClear();
    log::error("JNI exception at %s (cleared)", stage);
    return true;
}

// Load class using app's ClassLoader
static jclass load_class_with_app_cl(JNIEnv* env, std::string_view class_name) {
    JniLocalFrame frame(env, 32);
    if (!frame) {
        clear_jni_exception_and_log(env, "PushLocalFrame");
        return nullptr;
    }

    // ActivityThread.currentApplication()
    jclass at = env->FindClass("android/app/ActivityThread");
    if (!at) {
        clear_jni_exception_and_log(env, "FindClass(ActivityThread)");
        return nullptr;
    }

    jmethodID curApp = env->GetStaticMethodID(
        at, "currentApplication", "()Landroid/app/Application;");
    if (!curApp) {
        clear_jni_exception_and_log(
            env, "GetStaticMethodID(ActivityThread.currentApplication)");
        return nullptr;
    }

    jobject app = env->CallStaticObjectMethod(at, curApp);
    if (env->ExceptionCheck() || !app) {
        clear_jni_exception_and_log(
            env, "CallStaticObjectMethod(ActivityThread.currentApplication)");
        return nullptr;
    }

    // app.getClassLoader()
    jclass appCls = env->GetObjectClass(app);
    if (!appCls) {
        clear_jni_exception_and_log(env, "GetObjectClass(Application)");
        return nullptr;
    }

    jmethodID getCL =
        env->GetMethodID(appCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (!getCL) {
        clear_jni_exception_and_log(env,
                                    "GetMethodID(Application.getClassLoader)");
        return nullptr;
    }

    jobject cl = env->CallObjectMethod(app, getCL);
    if (env->ExceptionCheck() || !cl) {
        clear_jni_exception_and_log(
            env, "CallObjectMethod(Application.getClassLoader)");
        return nullptr;
    }

    // cl.loadClass("...")
    jclass clCls = env->GetObjectClass(cl);
    if (!clCls) {
        clear_jni_exception_and_log(env, "GetObjectClass(ClassLoader)");
        return nullptr;
    }

    jmethodID loadClass = env->GetMethodID(
        clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!loadClass) {
        clear_jni_exception_and_log(env,
                                    "GetMethodID(ClassLoader.loadClass)");
        return nullptr;
    }

    jstring name = env->NewStringUTF(class_name.data());
    if (!name) {
        clear_jni_exception_and_log(env, "NewStringUTF(class_name)");
        return nullptr;
    }

    jobject klassObj = env->CallObjectMethod(cl, loadClass, name);
    if (env->ExceptionCheck() || !klassObj) {
        clear_jni_exception_and_log(env,
                                    "CallObjectMethod(ClassLoader.loadClass)");
        return nullptr;
    }

    return static_cast<jclass>(frame.pop(klassObj));
}

// ----------------------------------------------------------------------------
// RESOLVER THREAD
// ----------------------------------------------------------------------------
static void resolver_thread_func() {
    uint32_t attempt = 0;
    const uint32_t max_attempts = config::kResolverTimeoutSec;

    for (;;) {
        attempt++;
        if (state::g_target_art_method.load()) {
            return;
        }
        if (attempt > max_attempts) {
            log::error("resolver: timeout after %u seconds, giving up",
                       max_attempts);
            return;
        }

        JavaVM* vm = get_created_jvm();
        if (!vm) {
            if ((attempt % 10) == 1) {
                log::info("resolver: waiting for JavaVM... (%u/%u)", attempt,
                          max_attempts);
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        JNIEnv* env = nullptr;
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || !env) {
            if ((attempt % 10) == 1) {
                log::error("resolver: AttachCurrentThread failed");
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        clear_jni_exception(env);
        jclass target = load_class_with_app_cl(env, config::kTargetClass);
        if (!target) {
            clear_jni_exception(env);
            vm->DetachCurrentThread();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        jmethodID mid = env->GetStaticMethodID(
            target, config::kTargetMethod.data(), config::kTargetSig.data());
        if (!mid) {
            if (!clear_jni_exception_and_log(env, "GetStaticMethodID(target)") &&
                (attempt % 10) == 1) {
                log::error("resolver: GetStaticMethodID returned null");
            }
            clear_jni_exception(env);
            vm->DetachCurrentThread();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        state::g_target_art_method.store(ArtMethodHandle(mid));
        log::info("resolved target ArtMethod*=%p for %s.%s%s", mid,
                  config::kTargetClass.data(), config::kTargetMethod.data(),
                  config::kTargetSig.data());
        vm->DetachCurrentThread();
        return;
    }
}

// ----------------------------------------------------------------------------
// QBDI TRACE CONTEXT
// ----------------------------------------------------------------------------
struct TraceCtx {
    uint64_t call_id = 0;
    pid_t tid = 0;
    uint64_t seq = 0;
    uint64_t access_count = 0;
    std::string buf;
};

// ----------------------------------------------------------------------------
// JNI WRAPPER
// ----------------------------------------------------------------------------
using LocalAESWork_t =
    jbyteArray (*)(JNIEnv*, jclass, jbyteArray, jint, jbyteArray);

static jbyteArray call_real_and_clear_exception(LocalAESWork_t real,
                                                 JNIEnv* env, jclass clazz,
                                                 jbyteArray bArr, jint i2,
                                                 jbyteArray bArr2) {
    jbyteArray ret = real(env, clazz, bArr, i2, bArr2);
    clear_jni_exception(env);
    return ret;
}

// The trace wrapper function
static jbyteArray trace_localAESWork(JNIEnv* env, jclass clazz,
                                      jbyteArray bArr, jint i2,
                                      jbyteArray bArr2) {
    static thread_local bool in_trace = false;
    RecursionGuard guard(in_trace);

    if (guard.was_recursive()) {
        auto native = state::g_target_native.load();
        if (native) {
            return native.as<LocalAESWork_t>()(env, clazz, bArr, i2, bArr2);
        }
        return nullptr;
    }

    const uint64_t call_id = ++state::g_call_id;
    const pid_t tid = gettid_fast();

    auto native = state::g_target_native.load();
    if (!native) {
        return nullptr;
    }
    auto real = native.as<LocalAESWork_t>();

    TraceCtx tctx{};
    tctx.call_id = call_id;
    tctx.tid = tid;
    tctx.buf.reserve(1 << 20);

    using Clock = std::chrono::steady_clock;
    auto start_time = Clock::now();

    fmt::appendf(tctx.buf,
                 "BEGIN tid=%d call=%llu native=%p env=%p clazz=%p bArr=%p "
                 "i2=%d bArr2=%p\n",
                 tid, static_cast<unsigned long long>(call_id), native.ptr, env,
                 clazz, bArr, i2, bArr2);

    auto finish = [&](jbyteArray ret, const char* note) -> jbyteArray {
        auto end_time = Clock::now();
        auto cost_us = std::chrono::duration_cast<std::chrono::microseconds>(
                           end_time - start_time)
                           .count();

        fmt::appendf(tctx.buf,
                     "END tid=%d call=%llu ret=%p mem_events=%llu "
                     "cost_us=%lld%s%s\n",
                     tid, static_cast<unsigned long long>(call_id), ret,
                     static_cast<unsigned long long>(tctx.access_count),
                     static_cast<long long>(cost_us),
                     note ? " note=" : "", note ? note : "");

        append_to_file(tctx.buf);
        return ret;
    };

    // Use QBDI C++ API with RAII
    QBDI::VM vm;

    // Instrument target module
    bool instrument_ok = vm.addInstrumentedModuleFromAddr(to_rword(native.ptr));
    if (!instrument_ok) {
        instrument_ok = vm.instrumentAllExecutableMaps();
    }
    if (!instrument_ok) {
        return finish(
            call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2),
            "instrumentation failed");
    }

    // Enable memory access recording
    if (!vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE)) {
        return finish(
            call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2),
            "recordMemoryAccess unsupported");
    }

    // Register memory access callback using lambda
    uint32_t memcb_id = vm.addMemAccessCB(
        QBDI::MEMORY_READ_WRITE,
        [&tctx](QBDI::VMInstanceRef vm_ref, QBDI::GPRState*,
                QBDI::FPRState*) -> QBDI::VMAction {
            auto accesses = vm_ref->getInstMemoryAccess();
            if (accesses.empty()) {
                return QBDI::CONTINUE;
            }

            tctx.seq++;

            for (const auto& m : accesses) {
                const char rw = (m.type & QBDI::MEMORY_WRITE) ? 'W' : 'R';
                fmt::appendf(
                    tctx.buf,
                    "M tid=%d call=%llu seq=%llu %c inst=0x%016llx "
                    "addr=0x%016llx size=%u value=0x%016llx flags=0x%04x\n",
                    tctx.tid, static_cast<unsigned long long>(tctx.call_id),
                    static_cast<unsigned long long>(tctx.seq), rw,
                    static_cast<unsigned long long>(m.instAddress),
                    static_cast<unsigned long long>(m.accessAddress),
                    static_cast<unsigned>(m.size),
                    static_cast<unsigned long long>(m.value),
                    static_cast<unsigned>(m.flags));
                tctx.access_count++;
            }

            return QBDI::CONTINUE;
        });

    if (memcb_id == QBDI::INVALID_EVENTID) {
        return finish(
            call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2),
            "addMemAccessCB failed");
    }

    // Build arguments vector
    std::vector<QBDI::rword> args = {
        to_rword(env),   to_rword(clazz), to_rword(bArr),
        jint_to_rword(i2), to_rword(bArr2),
    };

    // Execute with QBDI
    QBDI::rword ret_raw = 0;
    bool exec_ok = vm.switchStackAndCall(&ret_raw, to_rword(native.ptr), args,
                                         config::kQBDIStackSize);

    jbyteArray ret = from_rword<_jbyteArray>(ret_raw);

    if (!exec_ok) {
        ret = call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2);
        return finish(ret, "switchStackAndCall failed");
    }

    return finish(ret, nullptr);
}

// ----------------------------------------------------------------------------
// GUM HOOK CALLBACKS
// ----------------------------------------------------------------------------
static bool is_in_libart(void* p) {
    Dl_info info{};
    if (dladdr(p, &info) == 0 || !info.dli_fname) return false;
    return std::strstr(info.dli_fname, "libart.so") != nullptr;
}

static void on_trampoline_enter(GumInvocationContext*, void*) {
    // Empty - we only care about the leave callback
}

static void on_trampoline_leave(GumInvocationContext* ic, void*) {
    auto target = state::g_target_art_method.load();
    if (!target) {
        return;
    }

    // artQuickGenericJniTrampoline(Thread*, ArtMethod** managed_sp, ...)
    void* managed_sp = gum_invocation_context_get_nth_argument(ic, 1);
    if (!managed_sp) return;

    void* called = *reinterpret_cast<void**>(managed_sp);
    if (called != target.ptr) {
        return;
    }

    void* native_code = gum_invocation_context_get_return_value(ic);
    if (!native_code) return;

    // Skip if still in libart resolver
    if (is_in_libart(native_code)) {
        log::info("target hit but nativeCode=%p still in libart (skip once)",
                  native_code);
        return;
    }

    // CAS to set native entry only once
    NativeEntryHandle expected{};
    NativeEntryHandle desired{native_code};
    if (state::g_target_native.compare_exchange_strong(expected, desired)) {
        log::info("captured target native entry: %p", native_code);
    }

    // Replace return value with our wrapper
    gum_invocation_context_replace_return_value(
        ic, reinterpret_cast<gpointer>(&trace_localAESWork));
}

// ----------------------------------------------------------------------------
// HOOK INSTALLATION
// ----------------------------------------------------------------------------

// Static storage for GObject pointers (must outlive the hooks)
static GObjectPtr<GumInterceptor> g_interceptor;
static GObjectPtr<GumInvocationListener> g_listener;

static void install_hooks() {
    gum_init_embedded();

    // Find artQuickGenericJniTrampoline
    GumAddress tramp =
        gum_module_find_export_by_name("libart.so", "artQuickGenericJniTrampoline");
    if (tramp == 0) {
        tramp = gum_module_find_symbol_by_name("libart.so",
                                               "artQuickGenericJniTrampoline");
    }
    if (tramp == 0) {
        log::error("failed to find artQuickGenericJniTrampoline in libart.so");
        return;
    }

    g_interceptor = make_gobject(gum_interceptor_obtain());
    if (!g_interceptor) {
        log::error("gum_interceptor_obtain failed");
        return;
    }

    // Use gum_make_call_listener instead of GObject boilerplate
    g_listener = make_gobject(gum_make_call_listener(
        on_trampoline_enter, on_trampoline_leave, nullptr, nullptr));
    if (!g_listener) {
        log::error("gum_make_call_listener failed");
        return;
    }

    gum_interceptor_begin_transaction(g_interceptor.get());
    GumAttachReturn attach_ret = gum_interceptor_attach(
        g_interceptor.get(), GSIZE_TO_POINTER(tramp), g_listener.get(), nullptr);
    gum_interceptor_end_transaction(g_interceptor.get());

    if (attach_ret != GUM_ATTACH_OK) {
        log::error("gum_interceptor_attach failed: %d",
                   static_cast<int>(attach_ret));
        return;
    }

    log::info("hooked artQuickGenericJniTrampoline @ %p",
              reinterpret_cast<void*>(tramp));
}

}  // namespace memtrace

// ============================================================================
// ENTRY POINT
// ============================================================================
__attribute__((constructor)) static void memtrace_init() {
    memtrace::install_hooks();

    // Start resolver thread using std::thread
    std::thread(memtrace::resolver_thread_func).detach();
}
