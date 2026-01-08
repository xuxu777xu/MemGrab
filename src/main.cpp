#include "../qbdi/include/QBDI.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

static FILE *g_log = nullptr;
static uint64_t g_reads = 0;
static uint64_t g_writes = 0;
static bool g_show_symbol = false; // 默认关闭符号解析

// 清理函数
static void cleanup(uint8_t *stack) {
  if (stack)
    QBDI::alignedFress(stack);
  if (g_log && g_log != stderr)
    fclose(g_log);
}

// 通过 /proc/self/maps 添加模块
static bool add_module_from_maps(QBDI::VM &vm, const std::string &pattern) {
  std::ifstream maps("/proc/self/maps");
  if (!maps.is_open()) {
    fprintf(g_log, "[!] Cannot open /proc/self/maps\n");
    return false;
  }
  std::string line;
  bool added = false;

  while (std::getline(maps, line)) {
    // 只找包含目标名字的可执行段
    if (line.find(pattern) == std::string::npos)
      continue;
    if (line.find("x") == std::string::npos)
      continue;

    unsigned long long start, end;
    if (sscanf(line.c_str(), "%llx-%llx", &start, &end) == 2) {
      vm.addInstrumentedRange((QBDI::rword)start, (QBDI::rword)end);
      fprintf(g_log, "[+] %s: 0x%llx - 0x%llx\n", pattern.c_str(), start, end);
      added = true;
    }
  }
  return added;
}

// 内存访问回调
static QBDI::VMAction on_mem_access(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr,
                                    QBDI::FPRState *fpr, void *data) {
  std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();

  for (const auto &a : accesses) {
    const char *type = (a.type == QBDI::MEMORY_READ)    ? "R"
                       : (a.type == QBDI::MEMORY_WRITE) ? "W"
                                                        : "RW";

    if (a.type & QBDI::MEMORY_READ)
      g_reads++;
    if (a.type & QBDI::MEMORY_WRITE)
      g_writes++;

    // 基本信息
    fprintf(g_log, "[%s] 0x%llx -> 0x%llx (%u)", type,
            (unsigned long long)a.instAddress,
            (unsigned long long)a.accessAddress, a.size);

    // 值
    if (!(a.flags & QBDI::MEMORY_UNKNOWN_VALUE)) {
      fprintf(g_log, " = 0x%llx", (unsigned long long)a.value);
    }

    // 符号解析（默认关闭，太慢）
    if (g_show_symbol) {
      const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
          QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL);
      if (inst && inst->moduleName) {
        fprintf(g_log, "  [%s", inst->moduleName);
        if (inst->symbolName) {
          fprintf(g_log, "!%s+0x%x", inst->symbolName, inst->symbolOffset);
        }
        fprintf(g_log, "]");
      }
    }

    fprintf(g_log, "\n");
  }

  return QBDI::CONTINUE;
}
// 要追踪的目标 so（改成你的目标）
static const std::vector<std::string> TARGET_MODULES = {
    "libtarget.so",
    "libnative-lib.so",
    // "libcrypto.so",
};

// 是否追踪 Java 层（通过 libart.so）
static const bool TRACE_JAVA = true;
// ================================

static void setup_instrumentation(QBDI::VM &vm) {
  fprintf(g_log, "=== Setting up instrumentation ===\n");

  // 追踪目标模块
  for (const auto &mod : TARGET_MODULES) {
    if (!add_module_from_maps(vm, mod)) {
      fprintf(g_log, "[-] Not found: %s\n", mod.c_str());
    }
  }

  // 追踪 Java 层
  if (TRACE_JAVA) {
    fprintf(g_log, "\n[*] Enabling Java layer tracing...\n");
    add_module_from_maps(vm, "libart.so");
    // 可选：追踪更多 ART 组件
    // add_module_from_maps(vm, "libart-compiler.so");
    // add_module_from_maps(vm, "libdexfile.so");
  }

  fprintf(g_log, "\n");
}
int main() {
  // 打开日志
  g_log = fopen("/data/local/tmp/mem_trace.log", "w");
  if (!g_log) {
    g_log = stderr;
    fprintf(stderr, "[!] Cannot open log file\n");
  }

  // 设置行缓冲，实时看到输出
  setvbuf(g_log, nullptr, _IOLBF, 0);

  fprintf(g_log, "=== QBDI Memory Tracer ===\n");
  fprintf(g_log, "Mode: Target SO + Java layer\n");
  fprintf(g_log, "TRACE_JAVA: %s\n\n", TRACE_JAVA ? "ON" : "OFF");

  // 创建 VM
  QBDI::VM vm;

  // 分配虚拟栈
  uint8_t *stack = nullptr;
  QBDI::GPRState *gpr = vm.getGPRState();
  if (!QBDI::allocateVirtualStack(gpr, 0x100000, &stack)) {
    fprintf(g_log, "[!] Failed to allocate stack\n");
    return 1;
  }

  // 设置插桩范围
  setup_instrumentation(vm);

  // 开启内存访问记录
  if (!vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE)) {
    fprintf(g_log, "[!] recordMemoryAccess failed\n");
    QBDI::alignedFree(stack);
    return 1;
  }

  // 注册回调
  vm.addMemAccessCB(QBDI::MEMORY_READ_WRITE, on_mem_access, nullptr);

  fprintf(g_log, "=== Tracing started ===\n\n");

  // ================================================
  // TODO: 在这里调用你要追踪的目标函数
  //
  // 例1：直接调用本进程的函数
  // QBDI::rword ret;
  // vm.call(&ret, (QBDI::rword)target_func, {arg1, arg2});
  //
  // 例2：通过 dlsym 获取目标函数
  // void *handle = dlopen("libtarget.so", RTLD_NOW);
  // void *func = dlsym(handle, "target_function");
  // vm.call(&ret, (QBDI::rword)func, {args...});
  // ================================================

  // 统计
  fprintf(g_log, "\n=== Statistics ===\n");
  fprintf(g_log, "Total reads:  %llu\n", (unsigned long long)g_reads);
  fprintf(g_log, "Total writes: %llu\n", (unsigned long long)g_writes);

  // 清理
  QBDI::alignedFree(stack);
  if (g_log != stderr)
    fclose(g_log);

  return 0;
}
