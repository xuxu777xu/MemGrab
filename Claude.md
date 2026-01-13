1. 设备环境：Android 13，已 root；libart.so 中 artJniMethodStart ：0000000000735cd0 T artJniMethodStart，只针对这台设备不做通用适配。
2. 注入方式：通过第三方工具 `dlopen` 注入 so。
3. 目标函数：Java 层 `public static native byte[] localAESWork(byte[] bArr, int i2, byte[] bArr2);`（签名 localAESWork([BI[B)[B）。
4. 目标定位约束：只提供 Java 层声明，不想关心 native 在哪个 so、也不想提供 native 地址/偏移。
5. 技术栈固定：必须用 Frida Gum + QBDI。
6. 规避检测：尽量不修改目标 so 的代码段以规避 CRC 检测（优先在 libart.so 侧 hook）。
7. 行为目标：只做内存监听（记录该函数执行期间的内存读写）。
8. 执行策略：允许重放（QBDI 再执行一次用于更细的内存访问采集）。
9. 输出：写到 `/data/data/<包名>/files/memtrace.log`（文件名固定 memtrace.log）。包名：com.lucky.luckyclient 方法名：com.luckincoffee.safeboxlib.CryptoHelper.localAESWork
10. 不直接修改代码文件，只给可抄写的代码。
