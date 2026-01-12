#include "../gum/frida-gum.h"
#include <android/log.h>
#include <dlfcn.h>

#define LOG_TAG "MemTrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 目标方法签名（待匹配）
static const char *TARGET_METHOD_NAME = "localAESWork([BI[B)[B";

// ArtMethod 结构（Android 13 ARM64）
struct ArtMethod {
  uint32_t declaring_class_;
  uint32_t access_flags_;
  uint32_t dex_code_item_offset_;
  uint32_t dex_method_index_;
  uint16_t method_index_;
  uint16_t hotness_count_;
  struct {
    void *data_; // native 方法的 JNI 入口
    void *entry_point_from_quick_compiled_code_;
  } ptr_sized_fields_;
};

static GumInterceptor *interceptor = nullptr;

// hook 回调
static void on_jni_method_start(GumInvocationContext *ctx, gpointer user_data) {
  void *thread = gum_invocation_context_get_nth_argument(ctx, 0);
  ArtMethod *method =
      (ArtMethod *)gum_invocation_context_get_nth_argument(ctx, 1);

  if (!method)
    return;

  // TODO: 解析 ArtMethod 获取方法名
  // 这里需要实现 art_parser.cpp 中的方法签名解析

  // 临时：打印地址用于调试
  LOGI("artJniMethodStart: thread=%p, method=%p, native_entry=%p", thread,
       method, method->ptr_sized_fields_.data_);

  // TODO: 匹配目标方法后，捕获参数并加入 trace 队列
}

extern "C" void on_library_load() {
  LOGI("MemTrace library loaded");

  gum_init_embedded();
  interceptor = gum_interceptor_obtain();

  // 查找 artJniMethodStart
  void *libart = dlopen("libart.so", RTLD_NOLOAD);
  if (!libart) {
    LOGE("Failed to find libart.so");
    return;
  }

  void *art_jni_method_start = dlsym(libart, "artJniMethodStart");
  if (!art_jni_method_start) {
    LOGE("Failed to find artJniMethodStart");
    return;
  }

  LOGI("Found artJniMethodStart at %p", art_jni_method_start);

  // 安装 hook
  GumInvocationListener *listener =
      gum_make_call_listener((GumInvocationCallback)on_jni_method_start,
                             NULL, // onLeave
                             NULL, // user_data
                             NULL  // destroy
      );

  gum_interceptor_begin_transaction(interceptor);
  gum_interceptor_attach(interceptor, art_jni_method_start, listener, NULL);
  gum_interceptor_end_transaction(interceptor);

  LOGI("Hook installed successfully");
}

// 注入入口
__attribute__((constructor)) static void init() { on_library_load(); }
