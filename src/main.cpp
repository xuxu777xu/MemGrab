#include "../gum/frida-gum.h"
#include "../qbdi/include/QBDI.h"
#include "../qbdi/include/QBDI/Memory.h"
#include "../qbdi/include/QBDI/VM_C.h"

#include <android/log.h>
#include <cstdio>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <mutex>
#include <string>
#include <time.h>

// config
// 输出文件固定位置（与注入进程同 uid 的私有目录；必须可写）
static const char kLogPath[] =
    "/data/data/com.example.exampleapp/files/memtrace.log";
// 目标 Java 层标识（用于解析出对应的 ArtMethod* / jmethodID）
static const char kTargetClass[] = "com.exampleapp.safeboxlib.CryptoHelper";
static const char kTargetMethod[] = "localAESWork";
static const char kTargetSig[] = "([BI[B)[B";
// QBDI switchStackAndCallA 使用的 DBI stack 大小（一般 128KB 以上更稳）
static constexpr uint32_t kQBDIStackSize = 0x20000;
// resolver 线程超时（秒），避免永驻
static constexpr uint32_t kResolverTimeoutSec = 300;

// ---------------- logging ----------------
#define LOG_TAG "memtrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static std::mutex g_file_lock;
static int g_log_fd = -1;  // 持久化 fd，减少 open/close 开销
static std::atomic<uint64_t> g_call_id{0};

static inline pid_t gettid_fast() {
    return static_cast<pid_t>(syscall(__NR_gettid));
}

// 追加格式化字符串到 std::string：避免固定栈 buf 溢出/截断。
static void appendf(std::string &out, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int n = vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);

    if (n <= 0) {
        va_end(ap_copy);
        return;
    }

    const size_t old_size = out.size();
    out.resize(old_size + static_cast<size_t>(n) + 1);
    vsnprintf(&out[old_size], static_cast<size_t>(n) + 1, fmt, ap_copy);
    va_end(ap_copy);
    out.pop_back(); // drop trailing '\0'
}

// 追加写入到固定日志文件：带全局互斥，处理 EINTR / partial write。
// 优化：持久化 fd 减少 syscall 开销。
static void append_to_file(const std::string &data) {
    std::lock_guard<std::mutex> lock(g_file_lock);
    if (g_log_fd < 0) {
        g_log_fd = open(kLogPath, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (g_log_fd < 0) {
            LOGE("open(%s) failed: %s", kLogPath, std::strerror(errno));
            return;
        }
    }
    const char* p = data.data();
    size_t remaining = data.size();
    while (remaining > 0) {
        ssize_t w = write(g_log_fd, p, remaining);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOGE("write(%s) failed: %s", kLogPath, std::strerror(errno));
            close(g_log_fd);
            g_log_fd = -1;
            break;
        }
        if (w == 0) {
            break;
        }
        p += static_cast<size_t>(w);
        remaining -= static_cast<size_t>(w);
    }
}

using QBDI::VMInstanceRef;
using QBDI::rword;

// ---------------- target method & native pointer ----------------
// g_target_art_method：目标方法对应的 ArtMethod*（ART 上 jmethodID 本质是一个稳定指针）。
// g_target_native：目标方法最终解析出的真实 JNI native 入口（不在 libart resolver 内）。
static std::atomic<void*> g_target_art_method{nullptr};   // ArtMethod*
static std::atomic<void*> g_target_native{nullptr};       // JNI 函数地址（真实实现，不在 libart）

// 注入场景下通常无法直接拿到 JavaVM*，这里用 JNI_GetCreatedJavaVMs 获取当前进程已创建的 VM。
static JavaVM* get_created_jvm() {
  JavaVM* vms[1] = { nullptr };
  jsize n = 0;
  if (JNI_GetCreatedJavaVMs(vms, 1, &n) != JNI_OK || n <= 0) {
    return nullptr;
  }
  return vms[0];
}

static void clear_jni_exception(JNIEnv* env) {
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
  }
}

static bool clear_jni_exception_and_log(JNIEnv* env, const char* stage) {
  if (env == nullptr) return false;
  if (!env->ExceptionCheck()) return false;
  env->ExceptionClear();
  LOGE("JNI exception at %s (cleared)", stage);
  return true;
}

// 用 App 的 ClassLoader 加载目标类：注入 so 的线程上下文可能不是应用 classloader。
// 入参 class_name_dot 形如 "com.example.Foo"（点分格式）。
static jclass load_class_with_app_cl(JNIEnv* env, const char* class_name_dot) {
  if (env->PushLocalFrame(32) < 0) {
    clear_jni_exception_and_log(env, "PushLocalFrame");
    return nullptr;
  }

  // ActivityThread.currentApplication()
  jclass at = env->FindClass("android/app/ActivityThread");
  if (at == nullptr) {
    clear_jni_exception_and_log(env, "FindClass(ActivityThread)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }
  jmethodID curApp = env->GetStaticMethodID(at, "currentApplication", "()Landroid/app/Application;");
  if (curApp == nullptr) {
    clear_jni_exception_and_log(env, "GetStaticMethodID(ActivityThread.currentApplication)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }
  jobject app = env->CallStaticObjectMethod(at, curApp);
  if (env->ExceptionCheck() || app == nullptr) {
    clear_jni_exception_and_log(env, "CallStaticObjectMethod(ActivityThread.currentApplication)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }

  // app.getClassLoader()
  jclass appCls = env->GetObjectClass(app);
  if (appCls == nullptr) {
    clear_jni_exception_and_log(env, "GetObjectClass(Application)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }
  jmethodID getCL = env->GetMethodID(appCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
  if (getCL == nullptr) {
    clear_jni_exception_and_log(env, "GetMethodID(Application.getClassLoader)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }
  jobject cl = env->CallObjectMethod(app, getCL);
  if (env->ExceptionCheck() || cl == nullptr) {
    clear_jni_exception_and_log(env, "CallObjectMethod(Application.getClassLoader)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }

  // cl.loadClass("com.xxx.XXX")，直接用 cl 的 class，避免在 native 线程 FindClass 失败
  jclass clCls = env->GetObjectClass(cl);
  if (clCls == nullptr) {
    clear_jni_exception_and_log(env, "GetObjectClass(ClassLoader)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }
  jmethodID loadClass = env->GetMethodID(clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  if (loadClass == nullptr) {
    clear_jni_exception_and_log(env, "GetMethodID(ClassLoader.loadClass)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }
  jstring name = env->NewStringUTF(class_name_dot);
  if (name == nullptr) {
    clear_jni_exception_and_log(env, "NewStringUTF(class_name)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }
  jobject klassObj = env->CallObjectMethod(cl, loadClass, name);
  if (env->ExceptionCheck() || klassObj == nullptr) {
    clear_jni_exception_and_log(env, "CallObjectMethod(ClassLoader.loadClass)");
    env->PopLocalFrame(nullptr);
    return nullptr;
  }

  jobject out = env->PopLocalFrame(klassObj);
  return static_cast<jclass>(out);
}

// 异步解析线程：等待 JavaVM 就绪后，解析目标方法的 jmethodID(=ArtMethod*)。
// 解析结果写入 g_target_art_method，供 trampoline hook 做指针级匹配。
// 增加超时机制避免线程永驻。
static void* resolver_thread(void*) {
  uint32_t attempt = 0;
  const uint32_t max_attempts = kResolverTimeoutSec;
  for (;;) {
    attempt++;
    if (g_target_art_method.load() != nullptr) {
      return nullptr;
    }
    if (attempt > max_attempts) {
      LOGE("resolver: timeout after %u seconds, giving up", max_attempts);
      return nullptr;
    }

    JavaVM* vm = get_created_jvm();
    if (vm == nullptr) {
      if ((attempt % 10) == 1) {
        LOGI("resolver: waiting for JavaVM... (%u/%u)", attempt, max_attempts);
      }
      sleep(1);
      continue;
    }

    JNIEnv* env = nullptr;
    if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || env == nullptr) {
      if ((attempt % 10) == 1) {
        LOGE("resolver: AttachCurrentThread failed");
      }
      sleep(1);
      continue;
    }

    clear_jni_exception(env);
    jclass target = load_class_with_app_cl(env, kTargetClass);
    if (target == nullptr) {
      clear_jni_exception(env);
      vm->DetachCurrentThread();
      sleep(1);
      continue;
    }

    jmethodID mid = env->GetStaticMethodID(target, kTargetMethod, kTargetSig);
    if (mid == nullptr) {
      if (clear_jni_exception_and_log(env, "GetStaticMethodID(target)") == false && (attempt % 10) == 1) {
        LOGE("resolver: GetStaticMethodID returned null");
      }
      clear_jni_exception(env);
      vm->DetachCurrentThread();
      sleep(1);
      continue;
    }

    g_target_art_method.store(reinterpret_cast<void*>(mid));
    LOGI("resolved target ArtMethod*=%p for %s.%s%s", mid, kTargetClass, kTargetMethod, kTargetSig);
    vm->DetachCurrentThread();
    return nullptr;
  }
}

// ---------------- QBDI trace callback ----------------
struct TraceCtx {
  uint64_t call_id = 0;
  pid_t tid = 0;
  uint64_t seq = 0;  // 全局序号，用于区分循环内同地址指令的多次执行
  uint64_t access_count = 0;
  std::string buf;
};

// QBDI 内存访问回调：当指令产生内存读写时触发。
// 通过 `qbdi_getInstMemoryAccess()` 拿到当前指令产生的访问列表（可能多条）。
static QBDI::VMAction mem_access_cb(VMInstanceRef vm,
                                   QBDI::GPRState*,
                                   QBDI::FPRState*,
                                   void* data) {
  auto* ctx = reinterpret_cast<TraceCtx*>(data);
  size_t n = 0;
  QBDI::MemoryAccess* ma = QBDI::qbdi_getInstMemoryAccess(vm, &n);
  if (ma == nullptr || n == 0) {
    return QBDI::CONTINUE;
  }

  ctx->seq++;

  for (size_t i = 0; i < n; i++) {
    const auto& m = ma[i];
    const char rw = (m.type & QBDI::MEMORY_WRITE) ? 'W' : 'R';
    appendf(ctx->buf,
            "M tid=%d call=%llu seq=%llu %c inst=0x%016llx addr=0x%016llx size=%u value=0x%016llx flags=0x%04x\n",
            ctx->tid,
            static_cast<unsigned long long>(ctx->call_id),
            static_cast<unsigned long long>(ctx->seq),
            rw,
            static_cast<unsigned long long>(m.instAddress),
            static_cast<unsigned long long>(m.accessAddress),
            static_cast<unsigned>(m.size),
            static_cast<unsigned long long>(m.value),
            static_cast<unsigned>(m.flags));
    ctx->access_count++;
  }

  return QBDI::CONTINUE;
}

// ---------------- JNI wrapper (被替换后实际执行) ----------------
using LocalAESWork_t = jbyteArray (*)(JNIEnv*, jclass, jbyteArray, jint, jbyteArray);

// fallback 调用：调用真实实现并清理可能的 JNI 异常
static jbyteArray call_real_and_clear_exception(LocalAESWork_t real, JNIEnv* env, jclass clazz, jbyteArray bArr, jint i2, jbyteArray bArr2) {
  jbyteArray ret = real(env, clazz, bArr, i2, bArr2);
  clear_jni_exception(env);
  return ret;
}

// 这个函数会被写到 trampoline 的"返回值位置"，从而被 ART 当作目标 JNI 入口执行。
//
// 行为：
// - 正常情况下：用 QBDI 运行真实 native 入口，并记录执行期间的内存读写
// - 失败兜底：QBDI 初始化失败则直接调用真实实现（不影响业务）
static jbyteArray trace_localAESWork(JNIEnv* env, jclass clazz, jbyteArray bArr, jint i2, jbyteArray bArr2) {
  static thread_local bool in_trace = false;
  if (in_trace) {
    // 防止递归（理论上不会发生，做个保险）
    auto real = reinterpret_cast<LocalAESWork_t>(g_target_native.load());
    return real ? real(env, clazz, bArr, i2, bArr2) : nullptr;
  }
  in_trace = true;

  const uint64_t call_id = ++g_call_id;
  const pid_t tid = gettid_fast();

  void* real_p = g_target_native.load();
  auto real = reinterpret_cast<LocalAESWork_t>(real_p);
  if (real == nullptr) {
    in_trace = false;
    return nullptr;
  }

  TraceCtx tctx{};
  tctx.call_id = call_id;
  tctx.tid = tid;
  tctx.buf.reserve(1 << 20);

  timespec ts0{}, ts1{};
  clock_gettime(CLOCK_MONOTONIC, &ts0);

  appendf(tctx.buf,
          "BEGIN tid=%d call=%llu native=%p env=%p clazz=%p bArr=%p i2=%d bArr2=%p\n",
           tid, static_cast<unsigned long long>(call_id), real_p, env, clazz, bArr, i2, bArr2);

  auto finish = [&](jbyteArray ret, const char* note) -> jbyteArray {
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    const uint64_t cost_us =
        static_cast<uint64_t>((ts1.tv_sec - ts0.tv_sec) * 1000000ULL) +
        static_cast<uint64_t>((ts1.tv_nsec - ts0.tv_nsec) / 1000ULL);

    appendf(tctx.buf,
            "END tid=%d call=%llu ret=%p mem_events=%llu cost_us=%llu%s%s\n",
            tid,
            static_cast<unsigned long long>(call_id),
            ret,
            static_cast<unsigned long long>(tctx.access_count),
            static_cast<unsigned long long>(cost_us),
            (note != nullptr) ? " note=" : "",
            (note != nullptr) ? note : "");

    append_to_file(tctx.buf);
    in_trace = false;
    return ret;
  };

  VMInstanceRef vm = nullptr;
  QBDI::qbdi_initVM(&vm, nullptr, nullptr, QBDI::NO_OPT);
  struct VmGuard {
    VMInstanceRef& vm;
    ~VmGuard() {
      if (vm != nullptr) {
        QBDI::qbdi_terminateVM(vm);
        vm = nullptr;
      }
    }
  } vm_guard{vm};

  if (vm == nullptr) {
    return finish(call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2), "qbdi_initVM failed");
  }

  // 只 instrument 目标 native 所在 module；若失败则回退到 instrumentAllExecutableMaps。
  bool instrument_ok = QBDI::qbdi_addInstrumentedModuleFromAddr(vm, reinterpret_cast<rword>(real_p));
  if (!instrument_ok) {
    instrument_ok = QBDI::qbdi_instrumentAllExecutableMaps(vm);
  }
  if (!instrument_ok) {
    return finish(call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2), "instrumentation failed");
  }

  // 开启内存访问记录，并注册回调（每条指令读写都会进 mem_access_cb）。
  if (!QBDI::qbdi_recordMemoryAccess(vm, QBDI::MEMORY_READ_WRITE)) {
    return finish(call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2), "qbdi_recordMemoryAccess unsupported");
  }
  const uint32_t memcb_id =
      QBDI::qbdi_addMemAccessCB(vm, QBDI::MEMORY_READ_WRITE, mem_access_cb, &tctx, QBDI::PRIORITY_DEFAULT);
  if (memcb_id == QBDI::INVALID_EVENTID) {
    return finish(call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2), "qbdi_addMemAccessCB failed");
  }

  // 按 AArch64 调用约定把参数作为 rword 数组传给 switchStackAndCallA：
  // (JNIEnv*, jclass, jbyteArray, jint, jbyteArray)
  // 注：jint (int32_t) 显式零扩展到 rword，避免符号扩展歧义
  const rword args[5] = {
      reinterpret_cast<rword>(env),
      reinterpret_cast<rword>(clazz),
      reinterpret_cast<rword>(bArr),
      static_cast<rword>(static_cast<uint32_t>(i2)),
      reinterpret_cast<rword>(bArr2),
  };

  rword ret_raw = 0;
  const bool exec_ok =
      QBDI::qbdi_switchStackAndCallA(vm, &ret_raw, reinterpret_cast<rword>(real_p), kQBDIStackSize, 5, args);
  jbyteArray ret = reinterpret_cast<jbyteArray>(ret_raw);

  if (!exec_ok) {
    ret = call_real_and_clear_exception(real, env, clazz, bArr, i2, bArr2);
    return finish(ret, "qbdi_switchStackAndCallA failed");
  }

  return finish(ret, nullptr);
}

// ---------------- Gum listener: hook artQuickGenericJniTrampoline ----------------
typedef struct _JniTrampolineListener JniTrampolineListener;
struct _JniTrampolineListener {
  GObject parent;
};

static void jni_trampoline_listener_iface_init(gpointer g_iface, gpointer iface_data);

#define JNI_TYPE_TRAMPOLINE_LISTENER (jni_trampoline_listener_get_type())
G_DECLARE_FINAL_TYPE(JniTrampolineListener, jni_trampoline_listener, JNI, TRAMPOLINE_LISTENER, GObject)
G_DEFINE_TYPE_EXTENDED(JniTrampolineListener,
                       jni_trampoline_listener,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER, jni_trampoline_listener_iface_init))

static void jni_trampoline_listener_on_enter(GumInvocationListener*, GumInvocationContext*) {}

static bool is_in_libart(void* p) {
  Dl_info info{};
  if (dladdr(p, &info) == 0 || info.dli_fname == nullptr) return false;
  return std::strstr(info.dli_fname, "libart.so") != nullptr;
}

// 当 artQuickGenericJniTrampoline 返回时，return value 通常是"将要跳转执行的 native 入口"。
// 通过读取参数里的 managed_sp，我们能拿到本次调用的 ArtMethod*，与目标方法做指针级匹配。
static void jni_trampoline_listener_on_leave(GumInvocationListener*, GumInvocationContext* ic) {
  void* target = g_target_art_method.load();
  if (target == nullptr) {
    return;
  }

  // artQuickGenericJniTrampoline(Thread* self, ArtMethod** managed_sp, uintptr_t* reserved_area)
  void* managed_sp = gum_invocation_context_get_nth_argument(ic, 1);
  if (managed_sp == nullptr) return;

  void* called = *reinterpret_cast<void**>(managed_sp); // ArtMethod*
  if (called != target) {
    return;
  }

  void* native_code = gum_invocation_context_get_return_value(ic);
  if (native_code == nullptr) return;

  // 第一次可能还在 libart 的 dlsym/resolve stub，先放过让 ART 解析完成
  if (is_in_libart(native_code)) {
    LOGI("target hit but nativeCode=%p still in libart (skip once for resolve)", native_code);
    return;
  }

  // 用 CAS 保证只设置一次真实入口，避免多线程竞态
  void* expected = nullptr;
  if (g_target_native.compare_exchange_strong(expected, native_code)) {
    LOGI("captured target native entry: %p", native_code);
  }
  // 无论 CAS 成功与否，都替换返回值为 wrapper
  gum_invocation_context_replace_return_value(ic, reinterpret_cast<gpointer>(&trace_localAESWork));
}

static void jni_trampoline_listener_class_init(JniTrampolineListenerClass*) {}
static void jni_trampoline_listener_init(JniTrampolineListener*) {}

static void jni_trampoline_listener_iface_init(gpointer g_iface, gpointer) {
  auto* iface = reinterpret_cast<GumInvocationListenerInterface*>(g_iface);
  iface->on_enter = jni_trampoline_listener_on_enter;
  iface->on_leave = jni_trampoline_listener_on_leave;
}

// ---------------- init entry ----------------
static void install_hooks() {
  gum_init_embedded();

  // 以 export/symbol 两种方式寻找 trampoline（不同 ROM/裁剪情况下符号表可能不同）。
  GumAddress tramp =
      gum_module_find_export_by_name("libart.so", "artQuickGenericJniTrampoline");
  if (tramp == 0) {
    tramp = gum_module_find_symbol_by_name("libart.so", "artQuickGenericJniTrampoline");
  }

  if (tramp == 0) {
    LOGE("failed to find artQuickGenericJniTrampoline in libart.so");
    return;
  }

  GumInterceptor* interceptor = gum_interceptor_obtain();
  if (interceptor == nullptr) {
    LOGE("gum_interceptor_obtain failed");
    return;
  }
  GumInvocationListener* listener =
      reinterpret_cast<GumInvocationListener*>(g_object_new(JNI_TYPE_TRAMPOLINE_LISTENER, nullptr));
  if (listener == nullptr) {
    LOGE("g_object_new(JniTrampolineListener) failed");
    return;
  }

  // attach listener：不改目标 so，仅在 libart.so 侧做拦截，降低完整性校验风险。
  gum_interceptor_begin_transaction(interceptor);
  GumAttachReturn attach_ret =
      gum_interceptor_attach(interceptor, GSIZE_TO_POINTER(tramp), listener, nullptr);
  gum_interceptor_end_transaction(interceptor);

  if (attach_ret != GUM_ATTACH_OK) {
    LOGE("gum_interceptor_attach failed: %d", static_cast<int>(attach_ret));
    return;
  }

  LOGI("hooked artQuickGenericJniTrampoline @ %p", reinterpret_cast<void*>(tramp));
}

__attribute__((constructor))
static void memtrace_init() {
  install_hooks();

  // 单独线程解析目标 ArtMethod*，避免 constructor 阶段 JavaVM/类加载未就绪。
  pthread_t th;
  int err = pthread_create(&th, nullptr, resolver_thread, nullptr);
  if (err != 0) {
    LOGE("pthread_create(resolver_thread) failed: %d", err);
    return;
  }
  err = pthread_detach(th);
  if (err != 0) {
    LOGE("pthread_detach(resolver_thread) failed: %d", err);
  }
}
