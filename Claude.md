# QBDI + Frida Gum：内存访问监听方案（高层设计）

## 需求与约束（原始参数原样保留）
1. 设备环境：Android 13，已 root；libart.so 中 `artJniMethodStart`：`0000000000735cd0 T artJniMethodStart`（只针对这台设备，不做通用适配）。
2. 生成的 so：通过第三方工具采用 `dlopen` 方式注入。
3. 目标函数：Java 层 `public static native byte[] localAESWork(byte[] bArr, int i2, byte[] bArr2);`（签名 `localAESWork([BI[B)[B`）。
4. 目标定位约束：只提供 Java 层声明，不想关心 native 在哪个 so、也不想提供 native 地址/偏移。
5. 技术栈固定：必须用 Frida Gum + QBDI。
6. 规避检测：尽量不修改目标 so 的代码段以规避 CRC 检测（优先在 libart.so 侧 hook）。
7. 行为目标：只做内存监听（记录该函数执行期间的内存读写）。
8. 执行策略：允许重放（QBDI 再执行一次用于更细的内存访问采集）。
9. 输出：写到 `/data/data/com.example.exampleapp/files/memtrace.log`（文件名固定 `memtrace.log`）。目标方法：`com.exampleapp.safeboxlib.CryptoHelper.localAESWork`。
10. 不直接修改代码文件，只给可抄写的代码。


## 高层实现方案（不依赖目标 so 地址输入）
目标是在不修改目标 so `.text` 的前提下，记录 `localAESWork` 执行期间的内存读写。可行的数据流如下：

1. **在 JNI 边界处识别目标调用**
   - 选择一个“JNI 调用边界”的拦截点（位于运行时/桥接层，而不是目标 so 的函数入口）。
   - 在该拦截点获得本次调用的：
     - 方法标识（等价于 `ArtMethod* / jmethodID` 的稳定指针）
     - 本次要执行的 native 入口指针（JNI 实现地址）
     - 传入参数（`JNIEnv*`、`jclass/jobject`、`jbyteArray`、`jint`、`jbyteArray`）
   - 用方法标识与 `com.exampleapp.safeboxlib.CryptoHelper.localAESWork([BI[B)[B` 对应的 `jmethodID` 做指针级匹配，保证只对目标方法生效。

2. **用 QBDI 对“真实 native 入口”做受控执行/重放**
   - 创建 QBDI VM，配置需要插桩的地址范围（可选：只插桩目标模块；或插桩所有可执行映射以覆盖跨模块调用）。
   - 开启 memory access logging（读/写）。
   - 注册回调，在回调中拉取并记录内存访问项（每条访问包含）：
     - 指令地址 `instAddress`
     - 访问地址 `accessAddress`
     - 类型 `READ/WRITE`
     - 大小 `size`
     - 访问值 `value`（若平台/配置支持）
     - 标志 `flags`
   - **重放模式**：允许先让原调用正常执行一次，再用同样参数在 QBDI 中重放一次用于采集（会产生双执行副作用，是否可接受由你决定）。
   - **受控替换模式**：在可控环境中可选择只执行一次（由 QBDI 执行真实入口）并把返回值透传回调用方。

3. **日志落盘**
   - 输出固定到：`/data/data/com.example.exampleapp/files/memtrace.log`
   - 建议每次调用写入清晰的 BEGIN/END 边界，便于离线分析。

## 日志格式建议
建议使用行式日志，便于 grep/解析：
- 调用边界：
  - `BEGIN tid=... native=... env=... bArr=... i2=... bArr2=...`
  - `END tid=... ret=... mem_events=... cost_us=...`
- 内存访问：
  - `M tid=... R|W inst=0x... addr=0x... size=... value=0x... flags=0x...`

## 落地到“可控环境”的两条实现路线（可选其一）
1. **Debug 构建集成路线**
   - 在你可编译的构建中（例如调试版），在 native 层对 `localAESWork` 的 JNI 入口做包装：由 wrapper 调用真实实现并在内部用 QBDI 采集。
   - 优点：不需要对运行时注入/不需要绕过完整性检测点；工程稳定。
   - 缺点：需要你能改包或控制构建。

2. **Test harness 路线**
   - 在同进程内创建一个最小调用环境（JNI + 参数构造），直接调用目标 JNI 入口指针，并用 QBDI 采集。
   - 优点：采集可控、可重复、便于对比不同输入。
   - 缺点：需要你能获得“真实 JNI 入口指针”（通过导出符号、注册表、或你自有代码暴露）。

## 需要你确认的技术选项（仅技术层面）
- 采集范围：只覆盖目标模块
- 采集粒度：按指令
- 重放策略：不接受双执行副作用（含随机数、计数器、I/O、缓存等）？

