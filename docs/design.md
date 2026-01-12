# 通用内存追踪方案

## 目标

通过 Gum Interceptor 捕获参数 + QBDI 重放 trace，记录目标函数执行过程中的所有内存访问。

## 设计原则

1. **不触发 CRC**：只 hook libart.so，不碰目标 so 代码段
2. **被动发现 + 主动 trace**：Interceptor 捕获调用参数，QBDI 重放执行收集精细 trace
3. **通用性**：改签名匹配即可适配任意 native 函数

## 目标函数示例

```java
com.luckincoffee.safeboxlib.CryptoHelper.localAESWork(byte[], int, byte[])
```

## 架构

```
┌─────────────────────────────────────────────────────────┐
│  阶段 1：被动发现 + 参数捕获                              │
│                                                         │
│  Gum Interceptor                                        │
│  Hook: artJniMethodStart(Thread*, ArtMethod*)           │
│        ↑ 在 libart.so，不触发目标 so 的 CRC 检测         │
│                                                         │
│  onEnter:                                               │
│    1. thread = x0, method = x1 (ArtMethod*)             │
│    2. 解析方法签名，匹配目标（如 "localAESWork"）         │
│    3. 匹配失败 → 直接返回                                │
│    4. 匹配成功:                                          │
│       - native_addr = method->entry_point_from_jni_     │
│       - 记录目标 so 代码段范围                           │
│       - 从 Thread* 获取 JNIEnv*                         │
│       - 保存 JNI 参数引用（jbyteArray input 等）         │
│       - 设置标记: pending_trace = true                  │
│                                                         │
│  onLeave:                                               │
│    1. if (!pending_trace) return                        │
│    2. 原函数已执行完，结果已产生                          │
│    3. 解析并保存参数实际内容:                             │
│       - input_data = GetByteArrayElements(input)        │
│       - output_data = 从返回值或 output 参数获取         │
│       - key_data = GetByteArrayElements(key)            │
│    4. 将参数加入待 trace 队列                            │
└─────────────────────────────────────────────────────────┘
                         │
                         │ 参数已捕获
                         ▼
┌─────────────────────────────────────────────────────────┐
│  阶段 2：QBDI 重放 trace                                 │
│                                                         │
│  异步/延迟执行（避免阻塞原调用）:                         │
│                                                         │
│  1. 从队列取出保存的参数                                 │
│  2. 构造 native 调用参数                                │
│  3. 启动 QBDI VM:                                       │
│     - addInstrumentedRange(so_code_start, so_code_end)  │
│     - addMemAccessCB(MEMORY_READ, trace_callback)       │
│  4. vm.call(native_addr, jnienv, obj, input, mode, key) │
│  5. 收集所有内存读取记录                                 │
│  6. 保存 trace 到文件                                   │
└─────────────────────────────────────────────────────────┘
```

## 内存访问回调

```cpp
VMAction trace_callback(VM& vm, GPRState* gpr, FPRState* fpr, void* data) {
    for (const auto& access : vm.getMemoryAccess()) {
        if (access.type == MEMORY_READ) {
            // 可选：过滤特定地址范围
            uint64_t pc_offset = access.instAddress - code_base;
            uint64_t addr = access.accessAddress;
            uint64_t value = access.value;

            trace_log("%lx R %lx %lx", pc_offset, addr, value);
        }
    }
    return CONTINUE;
}
```

## Trace 输出格式

```
# function: com.example.CryptoHelper.localAESWork
# input[0]: 00112233445566778899aabbccddeeff
# input[1]: 1
# input[2]: 000102030405060708090a0b0c0d0e0f
1a4 R 7f8a001000 63
1a8 R 7f8a001100 7c
1ac W 7f8a002000 de
...
```

- `R` = 读取，`W` = 写入
- 第一列：PC 相对于代码段基址的偏移
- 第二列：访问类型
- 第三列：内存地址
- 第四列：访问的值

## 文件结构

```
src/
  main.cpp          - 入口 + Gum Interceptor hook
  qbdi_tracer.cpp   - QBDI VM 管理 + 内存访问回调
  art_parser.cpp    - ArtMethod 解析、方法签名匹配
  jni_helper.cpp    - JNI 参数提取（Thread* → JNIEnv*，jbyteArray → uint8_t*）
  trace_writer.cpp  - trace 文件输出
```

## 依赖

- Frida Gum (libfrida-gum.a)
- QBDI (libQBDI.a)
- Android NDK (aarch64)

## 关键实现细节

### 1. ArtMethod 解析

```cpp
// ArtMethod 内存布局（Android 10+ ARM64）
struct ArtMethod {
    uint32_t declaring_class_;      // GcRoot<Class>
    uint32_t access_flags_;
    uint32_t dex_code_item_offset_;
    uint32_t dex_method_index_;
    uint16_t method_index_;
    uint16_t hotness_count_;
    struct PtrSizedFields {
        void* data_;
        void* entry_point_from_quick_compiled_code_;
    } ptr_sized_fields_;
};

// entry_point_from_jni_ 在 data_ 字段（对于 native 方法）
void* get_native_entry(ArtMethod* method) {
    if (method->access_flags_ & kAccNative) {
        return method->ptr_sized_fields_.data_;
    }
    return nullptr;
}
```

### 2. Thread* → JNIEnv*

```cpp
// JNIEnv 是 Thread 结构的一部分，通常在偏移 0
JNIEnv* get_jnienv_from_thread(void* thread) {
    return *reinterpret_cast<JNIEnv**>(thread);
}
```

### 3. 为什么重放执行是安全的

- AES/DES 等加密函数通常是**纯函数**（相同输入 → 相同输出）
- 重放执行不会产生副作用
- 如果目标函数有状态依赖，需要额外处理

## 扩展性

| 扩展方向     | 修改点                               |
| ------------ | ------------------------------------ |
| 新增目标函数 | 添加签名匹配规则                     |
| 过滤地址范围 | 配置监控地址范围，在 callback 中过滤 |
| 批量 trace   | 修改输入数据，多次调用 vm.call()     |
