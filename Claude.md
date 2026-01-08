This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

使用 QBDI 动态二进制插桩技术，在 Android ARM64 app 运行时**捕获内存中的数据**，用于逆向分析。

核心场景：

- 捕获加密/解密函数处理的明文、密钥
- 获取内存中解密后的字符串、配置
- 监控敏感数据的读写（如 token、密码）

**不是**单纯的 trace/日志，重点是**拿到有价值的数据内容**。

## Platform

Android AArch64 (API 23+)

## Build

```bash
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang++ \
    -std=c++17 \
    -I./qbdi/include \
    -L./qbdi/lib \
    -o mem_tracer \
    src/main.cpp \
    -lQBDI -ldl -static-libstdc++
```

注意事项

- 只插桩可执行段（r-xp），QBDI 翻译的是代码不是数据
- 加壳/内存加载的 so 需要用 addInstrumentedRange() 手动指定地址
- 必须调用 vm.call() 或 vm.run() 才会触发回调
- 符号解析开销大，默认关闭，可离线用 llvm-symbolizer 处理

  Workflow

不直接修改代码文件，给出代码由用户自行抄写。
