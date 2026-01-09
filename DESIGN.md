# MemGrab - Android 内存数据捕获工具设计方案

## 1. 项目目标

**核心功能:** 在 Android ARM64 应用运行时，捕获内存中流动的敏感数据（密钥、明文、token 等）

**应用场景:**
- 捕获加密/解密函数处理的明文、密钥
- 获取内存中解密后的字符串、配置
- 监控敏感数据的读写（如 token、密码）

**技术选型:** 纯 QBDI，不依赖 Frida

---

## 2. 系统架构

```
+-------------------------------------------------------------+
|                      MemGrab Tool                           |
+-------------------------------------------------------------+
|                                                             |
|  +-------------+    +-------------+    +-----------------+  |
|  |   Trigger   |--->|    QBDI     |--->|   Data Sink     |  |
|  |   Module    |    |     VM      |    |    (Output)     |  |
|  +-------------+    +-------------+    +-----------------+  |
|        |                  |                    |            |
|        v                  v                    v            |
|  +-----------+    +-------------+      +--------------+     |
|  | PLT Hook  |    | MemAccess   |      | File/Logcat  |     |
|  | or Manual |    | Callback    |      | Ring Buffer  |     |
|  +-----------+    +-------------+      +--------------+     |
|                          |                                  |
|                          v                                  |
|                  +---------------+                          |
|                  | Smart Capture |                          |
|                  | + Filter      |                          |
|                  +---------------+                          |
|                                                             |
+-------------------------------------------------------------+
```

---

## 3. 模块设计

### 3.1 Trigger Module（触发器）

**职责:** 决定何时启动 QBDI 插桩

#### 方案 A: PLT Hook（推荐用于精确触发）

```cpp
// hook.hpp
#pragma once
#include <cstdint>

// PLT Hook 结构
struct PLTHook {
    void* original;     // 原函数地址
    void* trampoline;   // 跳板地址
};

// Hook 目标 SO 的 PLT 表项
PLTHook* hook_plt(const char* so_name, const char* func_name, void* replacement);

// 恢复 hook
void unhook_plt(PLTHook* hook);
```

**实现思路:**
1. 解析目标 SO 的 ELF 结构，找到 `.plt` 和 `.got.plt` 段
2. 定位目标函数的 GOT 表项
3. 将 GOT 表项替换为我们的 wrapper 函数地址
4. 在 wrapper 中启动 QBDI 跟踪

#### 方案 B: 地址范围监控（当前 main.cpp 的方式）

```cpp
// 从 /proc/self/maps 读取模块地址范围
// 只监控可执行段 (r-xp)
void setup_range_trigger(QBDI::VM& vm, const std::string& module_pattern) {
    // 解析 maps，添加插桩范围
    add_module_from_maps(vm, module_pattern);
}
```

**适用场景:**
- 不知道具体函数名
- 想监控整个 SO 的行为
- 快速原型验证

---

### 3.2 QBDI Engine（核心引擎）

**职责:** 管理 QBDI VM 生命周期，执行插桩

```cpp
// engine.hpp
#pragma once
#include "QBDI.h"
#include <memory>
#include <functional>

class QBDIEngine {
public:
    using MemCallback = std::function<void(const QBDI::MemoryAccess&, QBDI::GPRState*)>;

    QBDIEngine();
    ~QBDIEngine();

    // 初始化 VM
    bool init();

    // 添加内存访问回调
    void set_mem_callback(MemCallback cb);

    // 添加插桩范围
    void add_range(uintptr_t start, uintptr_t end);

    // 从 maps 添加模块
    bool add_module(const std::string& pattern);

    // 执行目标函数（用于主动调用场景）
    bool call(void* func, const std::vector<QBDI::rword>& args, QBDI::rword* ret);

    // 获取 VM 实例（用于高级操作）
    QBDI::VM& vm() { return *vm_; }

private:
    std::unique_ptr<QBDI::VM> vm_;
    uint8_t* stack_ = nullptr;
    MemCallback mem_callback_;

    static QBDI::VMAction mem_access_handler(
        QBDI::VMInstanceRef vm,
        QBDI::GPRState* gpr,
        QBDI::FPRState* fpr,
        void* data
    );
};
```

**关键实现:**

```cpp
// engine.cpp
bool QBDIEngine::init() {
    vm_ = std::make_unique<QBDI::VM>();

    // 分配虚拟栈
    QBDI::GPRState* gpr = vm_->getGPRState();
    if (!QBDI::allocateVirtualStack(gpr, 0x100000, &stack_)) {
        return false;
    }

    // 启用内存访问记录
    if (!vm_->recordMemoryAccess(QBDI::MEMORY_READ_WRITE)) {
        return false;
    }

    // 注册回调
    vm_->addMemAccessCB(QBDI::MEMORY_READ_WRITE, mem_access_handler, this);

    return true;
}
```

---

### 3.3 Smart Capture（智能数据捕获）

**职责:** 根据访问模式判断捕获策略，而不是傻傻 dump 固定字节

```cpp
// capture.hpp
#pragma once
#include <cstdint>
#include <vector>

// 捕获记录
struct CaptureRecord {
    uint64_t timestamp;      // 时间戳
    uintptr_t pc;            // 指令地址
    uintptr_t address;       // 访问地址
    uint8_t type;            // R/W/RW
    uint16_t access_size;    // 原始访问大小
    uint16_t capture_size;   // 实际捕获大小
    std::vector<uint8_t> data;
};

class SmartCapture {
public:
    // 根据访问信息决定捕获策略
    CaptureRecord capture(const QBDI::MemoryAccess& access, QBDI::GPRState* gpr);

private:
    // 判断是否为加密块操作
    bool is_crypto_block_access(size_t size) {
        return size == 16 || size == 32 || size == 64;
    }

    // 判断是否为查表操作（S-box）
    bool is_table_lookup(size_t size) {
        return size == 1;
    }

    // 安全读取内存
    bool safe_read(void* dst, const void* src, size_t len);
};
```

**捕获策略:**

| 访问大小 | 推测场景 | 捕获策略 |
|---------|---------|---------|
| 1 字节 | S-box 查表 | 捕获周围 64 字节上下文 |
| 16 字节 | AES-128 块 | 完整捕获 16 字节 |
| 32 字节 | AES-256 块 / ChaCha | 完整捕获 32 字节 |
| 64 字节 | SHA-512 块 | 完整捕获 64 字节 |
| 其他 | 通用数据 | 捕获 min(size*2, 128) |

```cpp
// capture.cpp
CaptureRecord SmartCapture::capture(const QBDI::MemoryAccess& access, QBDI::GPRState* gpr) {
    CaptureRecord record;
    record.timestamp = get_timestamp_ns();
    record.pc = gpr->pc;
    record.address = access.accessAddress;
    record.type = access.type;
    record.access_size = access.size;

    // 决定捕获大小
    size_t capture_size;
    if (is_crypto_block_access(access.size)) {
        // AES/SHA 等块操作，完整捕获
        capture_size = access.size;
    } else if (is_table_lookup(access.size)) {
        // 查表操作，捕获上下文
        capture_size = 64;
    } else {
        // 默认策略
        capture_size = std::min(access.size * 2, (size_t)128);
    }

    record.capture_size = capture_size;
    record.data.resize(capture_size);

    // 安全读取
    if (!safe_read(record.data.data(), (void*)access.address, capture_size)) {
        record.data.clear();  // 读取失败
    }

    return record;
}
```

---

### 3.4 Address Filter（地址过滤器）

**职责:** 减少噪音数据，提高信噪比

```cpp
// filter.hpp
#pragma once
#include <vector>
#include <cstdint>

struct AddressRange {
    uintptr_t start;
    uintptr_t end;
};

class AddressFilter {
public:
    // 添加目标范围（只捕获这些范围内的访问）
    void add_target(uintptr_t start, uintptr_t end);

    // 添加排除范围（忽略这些范围内的访问）
    void add_exclude(uintptr_t start, uintptr_t end);

    // 设置栈范围（自动排除）
    void set_stack_range(uintptr_t sp, size_t stack_size);

    // 判断是否应该捕获
    bool should_capture(uintptr_t addr) const;

    // 从 /proc/self/maps 加载段信息
    void load_from_maps(const std::string& pattern, bool as_target);

private:
    std::vector<AddressRange> targets_;
    std::vector<AddressRange> excludes_;
    AddressRange stack_ = {0, 0};
};
```

**过滤规则:**

```cpp
// filter.cpp
bool AddressFilter::should_capture(uintptr_t addr) const {
    // 1. 排除栈
    if (addr >= stack_.start && addr < stack_.end) {
        return false;
    }

    // 2. 检查排除列表
    for (const auto& ex : excludes_) {
        if (addr >= ex.start && addr < ex.end) {
            return false;
        }
    }

    // 3. 如果设置了目标列表，只捕获目标范围
    if (!targets_.empty()) {
        for (const auto& t : targets_) {
            if (addr >= t.start && addr < t.end) {
                return true;
            }
        }
        return false;  // 不在任何目标范围内
    }

    // 4. 未设置目标时，全量捕获
    return true;
}
```

**典型配置:**

```cpp
AddressFilter filter;

// 场景1: 只关心 libcrypto.so 的数据段
filter.load_from_maps("libcrypto.so:.bss", true);
filter.load_from_maps("libcrypto.so:.data", true);

// 场景2: 排除 malloc 内部结构
filter.load_from_maps("libc.so", false);  // 作为排除项

// 场景3: 排除栈访问
filter.set_stack_range(sp, 0x100000);
```

---

### 3.5 Data Sink（数据输出）

**职责:** 高效持久化，避免 I/O 阻塞影响性能

```cpp
// sink.hpp
#pragma once
#include "capture.hpp"
#include <string>
#include <fstream>
#include <atomic>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>

class DataSink {
public:
    virtual ~DataSink() = default;
    virtual void write(const CaptureRecord& record) = 0;
    virtual void flush() = 0;
};

// 简单文件输出（同步，适合调试）
class FileSink : public DataSink {
public:
    explicit FileSink(const std::string& path);
    ~FileSink() override;

    void write(const CaptureRecord& record) override;
    void flush() override;

private:
    std::ofstream file_;
    std::mutex mutex_;
};

// 环形缓冲 + 异步写入（生产用）
class RingBufferSink : public DataSink {
public:
    RingBufferSink(const std::string& path, size_t buffer_size = 4 * 1024 * 1024);
    ~RingBufferSink() override;

    void write(const CaptureRecord& record) override;
    void flush() override;

private:
    void writer_thread();

    std::vector<uint8_t> buffer_;
    std::atomic<size_t> write_pos_{0};
    std::atomic<size_t> read_pos_{0};
    std::ofstream file_;
    std::thread writer_;
    std::atomic<bool> running_{true};
    std::mutex mutex_;
    std::condition_variable cv_;
};
```

**二进制输出格式:**

```
每条记录:
+----------+----------+--------+--------+----------+--------------+
| PC (8B)  | Addr(8B) |Type(1B)|AccSz(2B)|CapSz(2B)| Data (变长)  |
+----------+----------+--------+--------+----------+--------------+
| uint64   | uint64   | uint8  | uint16 | uint16   | uint8[CapSz] |
+----------+----------+--------+--------+----------+--------------+

文件头 (可选):
+----------+----------+----------+----------+
| Magic(4B)| Version  | Flags    | Reserved |
| "MGRB"   | uint16   | uint16   | uint32   |
+----------+----------+----------+----------+
```

---

## 4. 工作流程

### 4.1 初始化流程

```
+----------------+
| 加载 SO 注入   |
+-------+--------+
        |
        v
+----------------+
| 解析配置/参数  |
+-------+--------+
        |
        v
+----------------+
| 初始化 Engine  |
| (创建 VM)      |
+-------+--------+
        |
        v
+----------------+
| 设置 Filter    |
| (目标/排除范围)|
+-------+--------+
        |
        v
+----------------+
| 初始化 Sink    |
| (输出目标)     |
+-------+--------+
        |
        v
+----------------+
| 注册 Trigger   |
| (Hook/Range)   |
+-------+--------+
        |
        v
+----------------+
| 等待目标执行   |
+----------------+
```

### 4.2 运行时流程

```
目标函数被调用
        |
        v
+------------------+
| Trigger 触发     |
| (PLT Hook 命中)  |
+--------+---------+
         |
         v
+------------------+
| QBDI 开始跟踪    |
+--------+---------+
         |
         v
+------------------+
| 指令执行         |
| 产生内存访问     |
+--------+---------+
         |
         v
+------------------+
| MemAccess 回调   |
+--------+---------+
         |
         v
+------------------+     NO
| Filter 判断      |--------+
| should_capture?  |        |
+--------+---------+        |
         | YES              |
         v                  |
+------------------+        |
| SmartCapture     |        |
| 决定捕获策略     |        |
+--------+---------+        |
         |                  |
         v                  |
+------------------+        |
| Sink 写入        |<-------+
+--------+---------+
         |
         v
+------------------+
| 继续执行         |
+------------------+
```

---

## 5. 文件结构

```
qbdi_memory/
├── src/
│   ├── main.cpp           # 入口，初始化流程
│   ├── engine.hpp         # QBDI VM 封装
│   ├── engine.cpp
│   ├── trigger.hpp        # 触发器接口
│   ├── trigger_plt.cpp    # PLT Hook 实现
│   ├── trigger_range.cpp  # 地址范围触发实现
│   ├── capture.hpp        # 智能捕获逻辑
│   ├── capture.cpp
│   ├── filter.hpp         # 地址过滤器
│   ├── filter.cpp
│   ├── sink.hpp           # 输出接口
│   ├── sink_file.cpp      # 文件输出
│   ├── sink_ringbuf.cpp   # 环形缓冲输出
│   └── utils.hpp          # 工具函数（maps解析等）
├── tools/
│   ├── parser.py          # 离线解析二进制输出
│   ├── detect_crypto.py   # 算法特征识别
│   └── bruteforce.py      # 密钥爆破辅助
├── qbdi/
│   ├── include/
│   └── lib/
├── DESIGN.md              # 本文档
├── CLAUDE.md              # AI 辅助说明
└── build.sh               # 编译脚本
```

---

## 6. 编译

```bash
#!/bin/bash
# build.sh

NDK=/path/to/ndk
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
CC=$TOOLCHAIN/bin/aarch64-linux-android23-clang++

$CC -std=c++17 \
    -I./qbdi/include \
    -L./qbdi/lib \
    -o mem_grab \
    src/main.cpp \
    src/engine.cpp \
    src/capture.cpp \
    src/filter.cpp \
    src/sink_file.cpp \
    src/trigger_range.cpp \
    -lQBDI -ldl -static-libstdc++ \
    -fPIC -O2
```

---

## 7. 使用示例

### 7.1 基础用法（监控整个 SO）

```cpp
// main.cpp
#include "engine.hpp"
#include "filter.hpp"
#include "sink.hpp"

int main() {
    // 初始化
    QBDIEngine engine;
    engine.init();

    AddressFilter filter;
    filter.set_stack_range(engine.get_sp(), 0x100000);

    FileSink sink("/data/local/tmp/mem_grab.bin");

    // 设置回调
    engine.set_mem_callback([&](const QBDI::MemoryAccess& access, QBDI::GPRState* gpr) {
        if (filter.should_capture(access.accessAddress)) {
            SmartCapture cap;
            auto record = cap.capture(access, gpr);
            sink.write(record);
        }
    });

    // 添加目标模块
    engine.add_module("libtarget.so");

    // 调用目标函数
    void* func = dlsym(dlopen("libtarget.so", RTLD_NOW), "encrypt");
    QBDI::rword ret;
    engine.call(func, {arg1, arg2, arg3}, &ret);

    sink.flush();
    return 0;
}
```

### 7.2 进阶用法（只监控特定数据段）

```cpp
// 只关心 libcrypto.so 的堆数据
AddressFilter filter;
filter.load_from_maps("libcrypto.so", true);   // 目标
filter.load_from_maps("libc.so", false);        // 排除 libc 内部
filter.set_stack_range(sp, 0x100000);           // 排除栈
```

### 7.3 离线分析

```bash
# 解析二进制输出
python tools/parser.py mem_grab.bin -o mem_grab.txt

# 检测加密算法特征
python tools/detect_crypto.py mem_grab.bin
# Output:
# [AES S-box] Found at PC=0x7abc1234, Addr=0x7fff5678
# [Possible Key] 16 bytes @ 0x7fff8000

# 密钥爆破
python tools/bruteforce.py --algo aes --trace mem_grab.bin --ciphertext encrypted.bin
```

---

## 8. 性能优化

### 8.1 过滤优化

- **地址范围过滤:** 减少 90%+ 的无效捕获
- **栈访问过滤:** 栈操作频繁但价值低
- **代码段过滤:** 代码读取无需记录

### 8.2 I/O 优化

- **环形缓冲:** 避免每次访问都触发 I/O
- **异步写入:** 独立线程负责刷盘
- **批量写入:** 积累一定量后批量写

### 8.3 回调优化

- **快速判断:** Filter 检查放在最前面
- **延迟解析:** 符号解析在离线阶段做
- **避免内存分配:** 预分配 buffer

---

## 9. 与现有代码的关系

当前 [src/main.cpp](src/main.cpp) 是一个基础实现，包含:
- VM 初始化 ✓
- maps 解析 ✓
- 内存访问回调 ✓

本设计在此基础上增加:
- 模块化拆分（engine/filter/sink/capture）
- 智能捕获策略
- 高性能输出
- 离线分析工具链

**迁移路径:**
1. 保留现有 main.cpp 作为参考
2. 逐步抽取逻辑到独立模块
3. 添加新功能（智能捕获、过滤器）
4. 替换输出为二进制格式

---

## 10. 已知限制

1. **加壳 SO:** 需要用 `addInstrumentedRange()` 手动指定运行时地址
2. **多线程:** QBDI VM 不是线程安全的，需要 per-thread VM
3. **性能:** 全量 trace 开销大，生产环境必须加过滤
4. **自修改代码:** QBDI 对 JIT/自修改代码支持有限

---

## 11. 后续计划

- [ ] 实现 PLT Hook 触发器
- [ ] 实现环形缓冲 Sink
- [ ] 编写离线解析工具
- [ ] 添加算法特征库（AES/RSA/SM4 等）
- [ ] 支持配置文件（目标模块、过滤规则）
