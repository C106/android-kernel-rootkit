# lk1337 ARM64 内核调试模块

面向 ARM64 Android GKI 5.10 的进程内存与硬件断点模块，构建产物为 `lk1337.ko`。当前用户态 ABI 版本为 `6`，结构体和命令定义见 [debugger_uapi.h](debugger_uapi.h)。不提供 32 位 compat ioctl 接口。

## 功能与状态

| 功能 | 当前状态 |
| --- | --- |
| 进程内存读取、写入、映射基址查询 | 已有实现，受页驻留状态和访问权限限制 |
| 线程硬件断点与观察点 | 已有实现，通过 perf 管理 |
| 基于 PTE UXN 的执行断点（模拟硬件执行断点） | 已有实现，已设备实测通过（4 KB 页 / 2 MB 块 / 匿名可执行映射），见 [PTE UXN 执行断点](#pte-uxn-执行断点模拟硬件执行断点) |
| 命中记录、寄存器修改模板、FPSIMD 状态处理 | 已有实现，依赖目标 GKI 的内部结构和行为 |
| 用户态 FP 链回溯 | 可选命中记录，最多 32 层 |
| maps 过滤 | 已有实现；新增 CFI 改名符号解析并修掉若干缺陷，见 [maps 过滤](#maps-过滤) |
| 陀螺仪数据调整 | 回退到 syscall 层被动钩子，并**只改 system_server 发起的发送**，见 [陀螺仪数据修改](#陀螺仪数据修改) |
| 进程隐藏（memwatch，已并入本模块） | 已有实现，已设备实测通过，随 `lk1337.ko` 一起构建，见[进程隐藏（memwatch，已并入 lk1337）](#进程隐藏memwatch已并入-lk1337) |
| 线程级 TTBR 内存视图分离 | 已有实现，已设备实测通过（executor 看 source 视图、其他线程看 alter 视图），见 [TTBR 线程内存视图分离](#ttbr-线程内存视图分离) |
| 探针按需注册（`probe_mgr.h`） | 已有实现，空闲模块在内核里没有任何功能探针，见 [kprobe 延迟与按需注册](#kprobe-延迟与按需注册) |
| `cfi_bypass.h` | 独立辅助头文件，未被当前模块编译单元引用 |

“已有实现”仅表示代码存在，不表示已在所有设备或内核配置上验证。仓库包含内核模块源码、构建文件，以及进程隐藏的用户态控制器 `prochide/`；不包含内存/断点的用户态控制器或自动化测试程序。

## 构建

需要 Linux 构建环境、GNU Make、目标 ARM64 内核源码及其构建依赖、匹配的 Clang/LLVM 工具链。默认配置为：

| 变量 | 默认值 |
| --- | --- |
| `KDIR` | `$HOME/gki_clean/gki-5.10` |
| `OUT` | `$(KDIR)/out` |
| `CLANG_PREBUILT` | `$(KDIR)/../prebuilts/clang/host/linux-x86/clang-r416183b` |
| `ARCH` | `arm64` |
| `JOBS` | `16` |

在本目录执行，使用已完成构建、与目标设备匹配的内核输出：

```sh
make modules
```

覆盖路径的示例：

```sh
make modules \
  KDIR=/path/to/gki-5.10 \
  OUT=/path/to/kernel-out \
  CLANG_PREBUILT=/path/to/clang-r416183b
```

首次从默认 GKI 配置构建，按顺序执行：

```sh
make prepare
make kernel JOBS=16
make modules
```

`make prepare` 会在 `OUT` 中运行 `gki_defconfig`、`olddefconfig` 和 `modules_prepare`，会重置已有配置。已有设备专用配置时，不应直接用该目标替代设备的构建流程。`modules_prepare` 本身不生成完整的 `Module.symvers`，模块构建应使用匹配内核的符号版本文件；仅 vermagic 相同不足以保证 ABI 兼容。

模块依赖 kprobes、perf 硬件断点，以及当前实现使用的 `CONFIG_BPF_SYSCALL` 相关 perf 字段。还使用了 `fs/proc` 内部声明和非导出符号解析，不能视为适配任意 ARM64 内核的通用模块。

可选模块 `memwatch` 已并入 `lk1337.ko`：`memwatch.o` 是 `lk1337-objs` 的一个编译单元，不再产出独立的 `memwatch.ko`，也不再需要 `BUILD_MEMWATCH=1`。原有的 `BUILD_MEMWATCH` 开关已移除，`make modules` 只产出 `lk1337.ko`（其中包含进程隐藏功能）。

清理构建产物：

```sh
make clean
```

## 加载与通信

在目标设备的 root shell 中，切换到模块所在目录：

```sh
insmod ./lk1337.ko
dmesg | tail -n 80
# 关闭客户端持有的会话 fd 后卸载
rmmod lk1337
```

模块不创建设备节点。客户端通过 IPv4 socket 的 `inet_ioctl` 路径发送 `LK1337_BOOTSTRAP`，使用 `struct lk1337_bootstrap` 接收匿名会话 fd。请求前将 `fd` 初始化为 `-1`，`magic` 按 UAPI 填写；当前实现未校验该 magic 字段。

bootstrap 使用 task-work，在返回用户态前创建 fd。原 socket ioctl 路径仍会执行，因此不能仅凭该 ioctl 的返回值判断 bootstrap 是否成功，还需检查返回结构中的 `fd`。后续命令发送到这个匿名 fd。bootstrap 和会话 ioctl 均检查调用线程的 real/effective/saved UID 是否为 root。

每个会话独立维护断点；最后一个 fd 引用关闭时释放会话资源。maps 规则和陀螺仪配置是模块级状态，并非会话私有配置。

## 接口概览

命令号为 UAPI 中定义的整数，参数布局以头文件为准。

| 命令号 | 用途 |
| --- | --- |
| `601` / `602` / `603` | 读内存 / 写内存 / 按文件 basename 查询首个匹配映射的起始地址 |
| `610` / `611` | 创建 / 删除硬件断点 |
| `612` / `613` | 旧版命中记录 / 寄存器修改兼容接口 |
| `614` / `615` / `616` | 清空记录 / 设置寄存器模板 / 读取命中记录 |
| `617` / `618` | 暂停 / 恢复断点 |
| `620` | 陀螺仪数据调整配置：`enable`/`type_mask`/`add0`/`add1`；`enable=1` 时解析 system_server，找不到返回 `-ESRCH` |
| `621` 至 `628` | maps 规则、启用状态和 PID 范围配置 |
| `630` 至 `635` | TTBR 线程级内存视图：创建 / 更新 / 设置执行线程 / 清除 / 销毁 / 查询 |
| `641` 至 `645` | 进程隐藏：添加 / 移除 / 清空隐藏 PID、启用与查询（memwatch） |

`LK1337_BP_CREATE`（`610`）的 `flags` 支持 `LK1337_BP_F_UXN`，用页表 UXN 位的权限错误替代 perf 硬件断点来实现**执行**断点。创建、删除、暂停/恢复、命中读取（`616`）和寄存器模板（`615`）与硬件断点共用同一套接口，用户态无需区分后端。

### 内存与断点限制

- 内存传输单次最多 16 MiB，处理已驻留普通页、实现支持的 PMD 大页，以及**被换出到 zram 的页**；不会主动把页换回目标进程。跨页失败时，前面的页可能已完成传输。
- **被换出（swap entry）的页直接读 zram，目标完全不被触碰**：从 PTE 取 `swp_entry_t` → 用内核导出的 `swp_swap_info()` 拿到 `swap_info_struct` → `->bdev`（zram 块设备）→ 用 `bio` 把这一个 4 KB 块 `submit_bio_wait()` 读进**我们自己分配的页**，再 `kmap` 拷给调用者。解压由 zram 自己的块层完成（`drivers/block/zram/zram_drv.c` 的 `submit_bio` 路径），所以 SAME 填充页、不同压缩算法（lzo/lz4/zstd）、zsmalloc/zbud 后端都自动正确。设备实测：模块读出的页与直接 `dd if=/dev/block/zram0` 同一 offset 的 md5 完全一致，且读完后目标 PTE 仍是 swap entry（页没被换回、RSS 不变）；之前必然 `-EFAULT` 的 64 KB / 1 MB 读现已成功。
- **不自己实现 zram 内部寻址**：`zs_map_object`、`zs_unmap_object`、`zcomp_decompress`、`crypto_alloc_acomp` 全部未导出，`struct zram` / `zram_table_entry` 也在驱动私有头里；手工解压需要复刻这些布局并跟随 vendor 的压缩算法与 zs 后端，脆弱且不可移植。走块设备只需要 `swp_swap_info`（GPL 导出）、`bio_alloc`/`bio_add_page`/`submit_bio_wait`/`bio_put`。
- **只写映射（`-w-p`）可以读**：VMA 权限检查对齐 GUP 的 `FOLL_FORCE` 规则（`mm/gup.c:check_vma_flags`）——读操作在 `VM_READ` 缺失但 `VM_MAYREAD` 置位时放行。`VM_READ` 只是软件标志，arm64 把只写私有映射映射成 `PAGE_READONLY`（`PTE_USER|PTE_RDONLY`，AP[2:1]=「Read-only, EL0」），读不会缺页、只有写才 fault。实测某目标 `libUE4.so` 的 14.7 MB `.bss` 就是唯一的 `-w-p [anon:.bss]`（反读取加固），旧检查让其中所有全局量一律 `-EACCES`。
- **PROT_NONE 仍然拒绝**（`-EACCES`）：arm64 上 PROT_NONE 页 `pte_present()` 为真且带有效 PFN，所以放开 VMA 检查后必须显式用 `pte_protnone()` / `pmd_protnone()` 挡住，否则会变成可读。`--xp`（execute-only）同样保持拒绝。
- `PTE_SPECIAL` 页允许读：它标记共享零页与 KSM 页。映射零页得到的就是「未写过的匿名页」应有的全 0；KSM 页是普通匿名数据。设备映射仍被 `pte_devmap()` + `pfn_valid()` 排除。
- 仍然返回 `-EFAULT`（不伪造 0）的情况：**PTE 不存在**（从未缺页的匿名页——返回 0 会把「地址算错」静默掩盖）、**swap 区是文件而非块设备**、以及**对已被换出的页做写操作**（写需要真正的缺页 + COW，仍走 GUP 语义）。
- 内存写接口用于数据传输，不提供修改可执行代码所需的完整指令缓存同步保证；写路径仍要求 VMA 可写且 PTE `pte_write()`，**不做 COW**——对私有文件映射里尚未 COW 的页，直接 `memcpy` 会改到 page cache 页，这一项与 GUP 的 `FOLL_FORCE|FOLL_WRITE` 语义仍有差距。
- 内存写接口用于数据传输，不提供修改可执行代码所需的完整指令缓存同步保证；写路径仍要求 VMA 可写且 PTE `pte_write()`，**不做 COW**——对私有文件映射里尚未 COW 的页，直接 `memcpy` 会改到 page cache 页，这一项与 GUP 的 `FOLL_FORCE|FOLL_WRITE` 语义仍有差距。
- 创建断点时，`pid` 表示单个目标 TID，`0` 表示调用线程；不会自动覆盖线程组或后续创建的线程。
- 断点 `type` 为 `0` 执行、`1` 读、`2` 写、`3` 读写。执行断点长度必须为 4，地址必须按 4 字节对齐。
- 命中缓冲区默认 256 条，最多 4096 条。`LK1337_BP_F_DETAIL` 开启详细记录，`LK1337_BP_F_BACKTRACE` 必须配合详细记录使用；未开启详细记录时仅累计命中数。
- `LK1337_ONESHOT` 表示模板只应用一次；`LK1337_DRAIN` 表示读取后移除已返回记录。FPSIMD 状态是否成功捕获需检查命中标志和 `fp_unavailable`。

## PTE UXN 执行断点（模拟硬件断点）

ARM64 的 perf 硬件断点受 BRP 寄存器数量限制（通常 4–6 个），且是**线程级**的。设置 `LK1337_BP_F_UXN` 后，`610` 创建的是页表支撑的执行断点：把目标地址所在映射的 `PTE_UXN`（EL0 execute-never）置位，用指令权限故障代替调试寄存器，数量只受内存限制。

机制（`uxn_breakpoint.h`）：

1. 创建时对目标 mm 的页表做一次修改，置 `PTE_UXN`：4 KB 页改 PTE，2 MB 块映射改 PMD（`granule` 会在 dmesg 中记录为 `4K` / `2M`）。
2. EL0 从该映射取指触发 instruction abort（`ESR_ELx_EC_IABT_LOW`，FSC = permission fault）。**在 `fault_info[]` 上接管派发**：把指向 `do_page_fault` 的槽位（体系结构固定的 FSC `0x0D/0x0E/0x0F`，即权限故障 level 1/2/3）替换为本模块的处理函数。命中指令地址等于某个已注册地址时记录命中（复用 `LK1337_BP_HITS`/模板/FPSIMD 同一套逻辑），清除 `PTE_UXN` 并开启硬件单步，然后返回"已处理"，不投递任何信号。
3. 被"放行"的指令正常执行，单步异常由 `register_user_step_hook()` 注册的钩子认领（不投递 SIGTRAP），再通过 `task_work` 在返回用户态前重新置上 `PTE_UXN`。

为什么接管 `fault_info[]` 而不是探测缺页慢路径：`do_mem_abort()` 带 `NOKPROBE_SYMBOL()`、`do_page_fault()` 是 `__kprobes`、`el0_ia()` 是 `noinstr`，且该内核未开 ftrace，故障路径本身无法挂 kprobe。早期实现改为探测 `handle_mm_fault()`，但那样**只能覆盖走到慢路径的文件映射**：Android 的 speculative page fault 会在 `handle_pte_fault()` 内消化匿名 VMA 上"PTE 已存在"的缺页，返回 0，根本不会调用 `handle_mm_fault()`，于是 JIT 类匿名可执行页既观察不到、又会因 `PTE_UXN` 残留而无限缺页。直接接管派发就没有这个限制，也顺带**移除了缺页热路径上的常驻探针**。

### 只读内存的写入原语

`fault_info[]` 是 `const` 的 `.rodata`，在这份 GKI 布局里位于内核镜像的 **2 MB 块映射**中；而内核镜像在 linear map 里是 NOMAP（`map_mem()` 主动跳过），没有别名。所以：

- `set_memory_rw()` 不可用——它要求地址落在 `VM_ALLOC` 的 vmalloc 区。
- 临时 `vmap()` 别名也不可用（实测 oops）。
- 最终采用内核自己的 text-poke 手法：用 `__set_fixmap()`（kallsyms 解析）把目标页临时映射到 `FIX_TEXT_POKE0`，再用**一次对齐的 64 位写入**替换函数指针——单个对齐 64 位存存在 arm64 上是原子的，任何 CPU 都不会看到撕裂的指针。`FIX_TEXT_POKE0` 与 kprobes 共用，所以复用内核的 `patch_lock` 串行化。

两个真实内核细节：

- **物理地址必须用 `__pa_symbol()`**（即 `addr - kimage_voffset`），**不能用 `virt_to_page()`**：在 `CONFIG_SPARSEMEM_VMEMMAP=y` 且未开 `CONFIG_DEBUG_VIRTUAL` 时，arm64 的 `virt_to_page()` 是按 linear map 偏移推算 `struct page` 的，对内核镜像地址会算出垃圾页；用它喂 fixmap 会写到随机物理内存，表现为"无任何日志直接重启"。早期 `vmap()` 方案 oops 也是同一根因。
- 该厂商内核的 `__set_fixmap()` **在 set 路径不刷 TLB**（与上游不同），所以写完映射后自己 `flush_tlb_kernel_range()`。

### CFI

`do_mem_abort()` 通过 CFI 校验的间接调用进入 `fault_info[].fn`。处理函数 `lk1337_uxn_fault()` 用与 `struct fault_info::fn` **完全一致的原型**声明，并用 `__CFI_ADDRESSABLE()` 强制生成跳转表项，使核心内核的 `__cfi_slowpath()`/模块 `__cfi_check()` 能接受它；实测设备上被内核正常调用，无 CFI failure。

需要注意的是，表里存的并不是 `kallsyms` 里的 `do_page_fault` 地址：CFI 下编译出的函数地址引用指向函数的**跳转表项**（实测 `fault_info[13..15].fn = …006b8`，而 `do_page_fault = …11de0`）。所以槽位靠**体系结构固定的 FSC 索引**选择，而不是与 kallsyms 地址比对。

### 改保护动作（mprotect）与游离 UXN 位

目标对受保护映射做一次**真正的** `mprotect`（权限值确实变化，权限不变的调用会被内核短路、PTE 不动）会让内核重写 PTE/PMD，把我们的 `PTE_UXN` 一起抹掉，断点就静默失效了。处理方式：

- **不按区间追踪，而是"校验并重挂"**。区间追踪不可移植：执行重写的内部函数各家内核不同，实测目标设备上 `change_protection()` **根本没有被调用**（厂商内核的 mprotect 路径走的是别的函数，探针挂在上面从不触发）。现在在 `__arm64_sys_mprotect` / `__arm64_sys_pkey_mprotect` / `change_protection` 三个入口挂**返回前触发的校验**：只要该 mm 有 UXN 断点，就用 `task_work` 排一次重挂；工作函数在进程上下文（syscall 已释放 `mmap_write_lock`）里锁着 `mmap_read_lock` 重新置 `PTE_UXN`。`lk1337_uxn_protect()` 是幂等的，重复置位无害；该 mm 没有断点时整条路径直接返回。
- **游离 UXN 位的安全网**。`mremap` 会把 PTE 连同我们的 UXN 位一起搬到新地址，而登记表里的地址没变；此后再执行新地址就会命中一个"有 UXN 位但无人认领"的映射——内核的 `do_page_fault()` 认为这次缺页已处理，指令会**无限重新执行**（进程 `state=R`、`stime` 疯涨、PC 不前进）。所以在故障处理里加了一道判据：**可执行 VMA 上出现 UXN 位却不匹配任何已登记条目**时，直接清掉该位并放行。可执行映射上正常情况下不会存在 UXN 位，所以这条判据不会误伤真正的执行权限故障（那些 VMA 不是 `VM_EXEC`，仍走正常 SIGSEGV）。

### 不留下缺页计数痕迹

早期基于 `handle_mm_fault()` 探测的实现会让**每一次 UXN 命中都在目标自己的缺页计数器上留痕**：那次缺页确实走到了 `mm_account_fault()`，而它对任何成功缺页都 `current->min_flt++`。实测目标 100 次调用后 `getrusage(RUSAGE_SELF).ru_minflt` 从 `+1` 涨到 **`+827`**——目标只要在敏感函数前后各读一次 `getrusage()` 或 `/proc/self/stat` 的 `minflt` 字段，就能发现"这段代码被页表断点盯着"，不需要任何特权。

现在的接管方式从根上消除了它：处理函数属于 `do_mem_abort()` 里的 `inf->fn`，返回 0 后 `do_mem_abort()` 立即返回，**`do_page_fault()` → `handle_mm_fault()` → `mm_account_fault()` 这条链根本不会执行**。连带 `perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS)`、`count_vm_event(PGFAULT)` 也都不再触发。设备复测：

```
baseline  ru_minflt+1   stat_minflt+0
armed     ru_minflt+0   stat_minflt+0     (100 次命中)
```

除开计数本身，顺带的好处是不再走缺页慢路径（`__do_page_fault`、`mmap_read_lock`、`handle_mm_fault`），同样 100 次调用的耗时从约 11 ms 降到约 2.5 ms。

代码里另外做了一道**显式保证**：在由我们自己处理的两条返回路径上保存并回填 `current->min_flt`，这样即使换到一台把记账放在别处的内核，命中也不会渗进 `getrusage(2)`/`proc(5)`。转发给原始处理函数的故障**不回填**——那些是真实故障，记账本来就该保留。

设备实测（xaga，`5.10.226-android12-9-00047`，KernelSU root）：

| 用例 | 结果 |
| --- | --- |
| 文件映射的函数上设 UXN 断点，目标调用 5 次 | 5 次命中，`hit.addr == hit.before.pc ==` 断点地址，`LK1337_FP_VALID` 置位，`fp_unavailable=0` |
| **匿名可执行页**（`mmap(PROT_EXEC, MAP_ANONYMOUS)` 写入 `mov w0,#7; ret`） | 3 次调用 3 次命中 |
| **2 MB 块映射**（`MADV_HUGEPAGE` 匿名 RWX，`AnonHugePages: 2048 kB`） | dmesg `granule=2M`，3 次命中 |
| 同一页上两个不同地址各设一个断点 | 两个都各自命中 3 次 |
| **对受保护页做真正的 `mprotect`**（r-x → rwx → r-x） | 命中数 3 → 6 → 9，断点每次都重新武装 |
| **`mremap(MREMAP_FIXED)` 把受保护映射搬走后再执行** | 日志 `cleared stray UXN`，进程不挂死（未加安全网时会无限缺页） |
| **命中期间的缺页计数** | `ru_minflt` / `stat.minflt` 均为 `+0`（早期实现为 `+827`） |
| 目标进程在断点武装状态下退出 | `exit_mmap` 钩子回收页表项，之后 `611` 删除断点返回 0，模块无异常 |
| `rmmod` | `fault dispatch restored`，返回 0 |
| `/sys/kernel/debug/kprobes/list` | 只剩 `exit_mmap`，缺页热路径上无探针 |

限制与取舍：

- **映射粒度**：UXN 只作用于整个映射粒度。为保证断点仍然有效，该粒度内**非断点地址**的故障也走同样的"解除 → 单步 → 重新武装"流程。因此**断点武装期间该映射实际是按指令单步执行的**，4 KB 页上是整页单步，2 MB 块上是整块单步（代价大得多）。这是页表断点的固有代价，不是实现缺陷。
- **必须是可执行映射**（`VM_EXEC`）：不可执行的映射本来就取指不能，置 UXN 没有意义，创建返回 `-EACCES`。
- **块映射的 TLB 失效**：块表项不能用 `flush_tlb_page()`（只失效最后一级），必须 `flush_tlb_mm()` 做全层级 ASID 失效。
- **mm（线程组）级**：页表是进程共享的，进程内**所有线程**在该地址都会命中，与硬件断点的线程级语义不同。
- UXN 后端不支持 `LK1337_BP_F_BACKTRACE`（返回 `-EOPNOTSUPP`），命中记录发生在持有 raw spinlock 的原子上下文里；perf 后端使用 inatomic uaccess 记录可驻留的用户栈帧。
- `LK1337_BP_PAUSE`/`RESUME` 对 UXN 断点按 breakpoint 生效；同一页仍有其他启用断点时，页面 UXN 位保持设置。
- **接管是全局的**：模块加载期间，系统里所有权限故障都会先经过本模块的处理函数（非本功能的故障原样转发给保存的原始处理函数）。只在需要 UXN 断点时加载模块即可。
- **只有 mprotect 会被自动重挂**：`mmap`/`munmap`/`mremap` 等其他改动 VMA 的操作不会恢复断点（`mremap` 之后登记地址已经失效）。这些情况下**不会挂死**（安全网会清掉游离的 UXN 位），但断点实际上已失效，需要删除重建。
- 跨 CPU 的 TLB 一致性依赖 `flush_tlb_page()`/`flush_tlb_mm()` 的内共享广播；命中窗口内其他线程仍可能执行该映射（跳过命中）。


## maps 过滤

[maps_filter.h](maps_filter.h) 用 kprobe 把选定路径从目标进程的映射信息里隐藏，命令 `621` 至 `628` 配置规则、PID 选择与启用状态。默认是**全量模式**（对所有被读进程生效）。

| 探针 | 作用 |
| --- | --- |
| `show_map_vma` | 跳过 `/proc/<pid>/maps` 中命中的 VMA |
| `show_smap` | 跳过 `/proc/<pid>/smaps` 中命中的 VMA |
| `show_smaps_rollup` | 目标 mm 中存在命中 VMA 时抑制整条汇总记录 |
| `proc_map_files_get_link` / `_instantiate` / `_lookup` + `proc_fill_cache` | 屏蔽 `map_files` 目录项 |
| `proc_pid_readlink` | 屏蔽 `ls -l` 走 readlink 的路径 |

### CFI 改名符号的解析

同一份源码在两类内核上的符号拼写**不一样**，实测（`System.map` 与设备 `/proc/kallsyms` 对照）：

| 符号 | 构建内核 GKI `5.10.226-android12-9` | 设备 xaga `5.10.226-android12-9-00047-g4968e29b7f92` |
| --- | --- | --- |
| `show_map_vma` / `show_smap` / `show_smaps_rollup` | 只有 `name$f0f99e7d…`，**裸名不存在** | **裸名存在**，另有 `name.cfi_jt` |
| `proc_map_files_get_link` / `_instantiate` / `_lookup` / `proc_pid_readlink` | 只有 `name$181a70ca…` | **裸名存在**，另有 `name.cfi_jt` |
| `proc_fill_cache`、`proc_pid_lookup`、`do_send_sig_info`、`inet_ioctl`、`task_work_add` 等 | 裸名 | 裸名 |
| `smap_gather_stats` | 不存在（被 ThinLTO 内联） | 不存在（同样被内联） |

GKI 用 `-fsanitize-cfi-cross-dso` + `-fsplit-lto-unit`，把取了地址的内部链接函数改名为 `name$<hash>`；**后缀是每个编译单元一个，不是每个函数类型一个**（实测：本模块 `entry.o` 里 kprobe pre_handler 与 sendmsg 回调同为 `$4e8b0154…`，`memwatch.o` 是 `$cf7a1e40…`；内核里 `fs/proc/task_mmu.c` 那组同为 `$f0f99e7d…`，`fs/proc/base.c` 那组同为 `$181a70ca…`）。vendor 内核（MTK/Xiaomi）保留裸名，另给一个 `name.cfi_jt` 跳转表入口。kprobe 的 `symbol_name` 是精确匹配，所以**老代码在设备上能注册（maps 过滤在设备上本来就是可用的），在 GKI 构建内核上那 7 个探针一个都注册不上**；而在构建内核上唯一注册成功的是备用 `show_vma_header_prefix`，恰好是签名写错、必然 oops 的那个。

现在 `lk1337_register_kprobe()` 先按裸名注册（设备走这条），失败后用 kallsyms 前缀匹配 `name$<hex>` 再按地址注册（GKI 走这条）。匹配只接受全十六进制后缀，因此 `name$hash.cfi_jt`（跳转表入口）与 `name$hash.cold` 会被排除，命中的一定是函数本体；`.cfi_jt` 形式的入口不会被误选。`kallsyms_on_each_symbol` 未导出，其地址用「注册一次性 kprobe 读 `probe.addr`」的既有技巧取得，与 [ttbr_view.c](ttbr_view.c) 解析 `kallsyms_lookup_name` 同一手法（该函数在设备上也是裸名 `T`）。

### 语义与已知取舍

- 只对**非匿名映射**生效（`vm_file` 为空直接跳过）；匹配是完整路径转小写后的**子串**匹配，自定义规则入库时也转小写，因此加规则大小写不敏感。
- per-PID 模式比较的是**被读进程**，不是读者进程（`cat /proc/1234/maps` 看的是 1234），目标任务取自 `m->private`（`struct proc_maps_private`，定义在 `fs/proc/internal.h`）。默认全量模式直接返回，**不读 `m->private` 的任何字段**，所以常见路径不依赖 vendor 对 `proc_maps_private` 的布局；`smaps_rollup` 那条只读它的首字段 `inode`，mm 用 `get_task_mm()` 取，不去猜字段偏移。
- 跳过函数体靠把 `regs->pc` 指向 LR。`show_map_vma` 是 void，直接返回即可；`show_smap` 返回 `int` 且自身就是 seq 的 `.show` 回调，现在显式返回 `SEQ_SKIP`——此前它会把 `seq_file*` 当作返回值，低 32 位为负时让 `/proc/<pid>/smaps` 整个读失败。
- `smaps_rollup` 无法按 VMA 抑制：构建内核和设备内核都把 `smap_gather_stats()` 内联掉了（kallsyms 里不存在，无法 hook），汇总也无法在排除隐藏 VMA 后重算。现在的行为是**目标 mm 中存在命中 VMA 时该文件读出来是空的**，以免汇总数字与已过滤的 `/proc/<pid>/smaps` 自相矛盾。代价是留下「该进程 smaps_rollup 为空」这一特征，属于已知取舍；若更希望保留原始数字，把这一条改回不注册即可。
- 不再有 `show_vma_header_prefix` 备用 hook：它的真实签名是 `(m, start, end, flags, pgoff, dev, ino)`，没有 VMA 参数，旧实现对虚拟地址解引用必然 oops，而且只跳过头行也挡不住随后打印的映射路径。`show_map_vma` 解析失败时 maps 过滤直接记为不可用。
- 规则与 PID 列表用 raw spinlock 保护（原来在 kprobe 处理器里用 mutex，是潜在睡眠点）；`d_path` 改用共享缓冲区加锁，替代原来每个 VMA 一次 `kmalloc(PATH_MAX, GFP_ATOMIC)`。命中日志改为 `pr_info_ratelimited` 且只打规则名，不再逐条打印完整路径。
- 未覆盖 `ptrace`、`/proc/<pid>/numa_maps`、coredump 等信息源。

## 陀螺仪数据修改

陀螺仪改写走 **syscall 层的被动钩子**：kprobe 挂在 `__arm64_sys_sendto` 的 `pre_handler` 上，并且**只重写 system_server 发起的发送**（sensor 服务在 system_server 内，按发送者的线程组 id 过滤），其他任何进程的 `sendto()` 完全不受影响。不遍历 fd 表、不替换 `proto_ops`、不持 file 引用。

机制：

1. `enable=1` 时用 `for_each_process` 按 `comm == "system_server"` 解析出它的 **tgid** 并缓存（`lk1337_gyro_find_server()`）；找不到就返回 `-ESRCH`，不启用、不落参数。
2. 钩子第一道门就是 `task_tgid_vnr(current) == gyro_server_tgid`——按**线程组**比较，所以 system_server 内部名为 `SensorService` 之类的线程也能命中；`enable=0` 时清空 tgid，钩子退回完全被动。
3. 其余闸门：`len != 0`、`len ≤ 2 MiB`、`len % 0x68 == 0`；逐条读 `+8` 的 type（4 → `mask` bit0，16 → bit1），把 `+24/+28` 用 `lk1337_fp32_add()` 加上 add0/add1。
4. 改的是**调用者的用户态缓冲区**：enable 时预分配 2 MiB 内核 scratch buffer，pre-handler 只用 inatomic uaccess 读写；用户页未驻留或不可访问时跳过改写，原 `sendto` 继续执行。

与新版参考模块（`hpjy/5.10.ko`，`name=paradise`，vermagic `5.10.252-dirty`）的差异：

| 点 | 参考模块 | 本模块 |
| --- | --- | --- |
| 注入层 | 替换 system_server 里 AF_UNIX `SOCK_SEQPACKET` socket 的 `proto_ops->sendmsg` | kprobe `__arm64_sys_sendto` |
| 作用对象 | 内核态消息副本，`iov_iter_kvec` 重发，调用者不可见 | 调用者用户态缓冲区，`copy_to_user` 写回 |
| 生效范围 | 仅被钩住的那几个 socket | 仅 system_server 的发送（tgid 过滤） |
| 未命中负载时的附带行为 | 会**永久脱钩**该 socket，需 enable 关开才能重挂 | 无副作用 |
| `+24/+28` 加法 | 截断、无舍入、NaN/次正规不特判 | `lk1337_fp32_add`：guard/round/sticky 的 round-to-nearest-even + NaN/Inf payload 保留 |

> 参考模块那套 `proto_ops->sendmsg` 方案曾移植过一轮，现已回退；移植版补丁保存在 `prochide/gyro-port.patch`（该目录被 `.gitignore` 忽略），需要时 `git apply` 即可取回。

限制：

- 只覆盖 `sendto`/`send()` syscall；若发送走 `write`/`writev`/`sendmsg` 则不经过这个钩子。实测该目标上 sensor 数据确实是 `sendto`（ftrace：`__arm64_sys_sendto` 上 `len=104/208/312`，来自 `SensorService` 线程）。
- 发送者判定**不会失效**：快路径比较缓存的 tgid，一旦不匹配就回退到组长 `comm == "system_server"` 并刷新缓存——system_server 重启（跨重启、zygote 重启）后无需重新 `enable`。若只缓存一次 tgid，重启后过滤器会永久挡住所有发送。
- `enable` 后会在 dmesg 打印前 6 条改写采样（`x=<改前>-><改后>`、`y=`、`add=`），可直接确认改写是否生效；预算用完即停，不会长期刷屏。
- add0/add1 是 **float 的位模式**（`+24/+28` 的原始语义），不是整数值：要加 1.0 应传 `0x3f800000`，传 `1`（`0x00000001`）是 1e-45 级别的次正规数，等于没改。
- 只看 `len % 0x68` 和 `+8` 的 type，**不校验记录版本字段**（参考模块要求每条首 u32 等于 `0x68`）。
- 改动对发送方可见（用户缓冲区被写回）；只动 x/y 角速度，不动 `timestamp`/`sensor`/`data[2..]`，输出在时间戳与速率上不自洽；不区分接收方。

实测（设备 `5.10.226-android12-9-00047`，xaga）：`pidof system_server` = 1683，`ioctl 620 enable=1 mask=3` 后 dmesg 打出 `gyro: enabled … tgid=1683`，与真实 pid 一致；`enable=0` 后 `tgid=0`。

## 进程隐藏（memwatch，已并入 lk1337）

`memwatch` 的功能已从独立模块并入 `lk1337.ko`：把选定的 PID 从 `/proc` 枚举中隐藏、屏蔽 `/proc/<pid>` 直接访问，并让发往隐藏 PID 的信号静默成功。源码为 [memwatch.c](memwatch.c)（实现与模块级状态）、[memwatch.h](memwatch.h)（对 `entry.c` 的接口）、[memwatch_uapi.h](memwatch_uapi.h)（用户态 ABI）。

整合方式：

- `LK1337_BOOTSTRAP` 与 `MW_BOOTSTRAP`（`0x4d570001`）由同一个 `inet_ioctl` 探针处理，**都返回同一个 lk1337 会话 fd**；两个 bootstrap 结构体布局相同（`{u32 magic; s32 fd;}`），由 `BUILD_BUG_ON` 在编译期校验。
- 用户态命令 `641` 至 `645` 由该会话 fd 的 `lk1337_dispatch()` 直接分发，因此现有 `mwctl` 无需改动；lk1337 客户端拿到的 fd 也能直接发这些命令。
- `task_work_add` 复用 lk1337 已有的解析结果，不再单独解析；`memwatch` 自己不再需要匿名 fd、`file_operations` 和 `mw_root()` 检查（会话 ioctl 已做 root 校验）。
- 隐藏列表、enable 状态和 flags 是**模块级共享状态**，不随会话销毁；关闭最后一个 fd 释放的是断点等会话资源。
- 三个 hook 注册失败现在是**非致命**的：`lk1337` 照常加载，仅对应功能不可用。`MW_HIDE_ENABLE` 会把缺失 hook 的 flag 从生效值中屏蔽，`MW_HIDE_QUERY` 只报告真正生效的 flag。

> 身份变化：模块名、`/proc/modules`、`modinfo` 描述和匿名 fd 名现在都随 `lk1337.ko`（模块名 `lk1337`，描述 "ARM64 process memory and hardware breakpoint debugger"，fd 名 `[lk1337]`）；`memwatch.c` 内部保留了 `pr_fmt`，因此它的 dmesg 行仍以 `memwatch: ` 开头，模块级日志则以 `lk1337: ` 开头。原 `memwatch` 的无害模块身份（模块名 `memwatch`、"Memory mapping access watchdog"、fd 名 `[memwatch]`）不再存在。需要保留该身份时应继续使用独立的 `memwatch.ko`，而不是本次合并产物。

三个 hook 点及其效果：

| 符号 | 效果 |
| --- | --- |
| `proc_fill_cache`（procfs 根目录枚举） | 过滤 `/proc` 枚举，`ps` 不再列出隐藏 PID |
| `proc_pid_lookup` | 屏蔽 `/proc/<pid>` 直接访问，返回 `-ENOENT` |
| `do_send_sig_info` | 对隐藏 PID 的信号静默成功，`kill` 返回 0 但信号被丢弃 |

procfs 根目录按 **superblock 类型**识别（`sb->s_type->name == "proc"`），不按挂载点 dentry 名：实测某 vendor 内核上 `/proc` 挂载根 dentry 名为 `/` 而非 `proc`，名称判据会漏判；按 superblock 识别对 bind mount 同样成立。

语义：

- 默认仅对非 root 读者隐藏；被隐藏进程自己始终可见（线程组 tgid 豁免）。
- `MW_F_HIDE_ROOT` 使 root 读者也看不到。
- `pid 0` 表示调用者线程组。
- 最多隐藏 16 个 PID。
- 进程组/会话信号（PGID/SID）不拦截。
- 三个 hook 全部为可选：注册失败只关闭对应功能（`proc_fill_cache` → 枚举过滤，`proc_pid_lookup` → 直接访问屏蔽，`do_send_sig_info` → 信号隐藏），三者都失败时隐藏功能不可用，但不影响 `lk1337` 加载。
- `proc_fill_cache` 上同时存在 lk1337 自身的 maps 过滤探针。kprobe 聚合处理在第一个认领该条目的 `pre_handler` 处停止，两个 handler 都只在确定要丢弃条目时返回 1，因此同一地址共存不会互相误伤或读到已被改写后的寄存器。

限制：

- 不覆盖 ptrace attach、`/proc/net` 等其他信息源。
- `/proc/<pid>/task` 枚举本身未直接过滤，但目录被 `proc_pid_lookup` 屏蔽后，非 root 读者不可达。
- 已对 `/proc/<pid>` 建立正向 dcache 的读者在 `drop_caches` 前仍可能通过缓存 dentry 访问（VFS 正常行为，隐藏对新建路径即时生效）。

实测状态：作为独立 `memwatch.ko` 时已在 `5.10.226-android12-9` vendor 内核（xaga，`hidepid=invisible` 挂载）上完成加载、枚举/访问/信号隐藏、`MW_F_HIDE_ROOT`、enable/disable 切换与卸载验证；该内核比基线多 47 个 vendor 提交，vermagic 需按设备内核完整版本串适配（`llvm-objcopy --update-section .modinfo`）后加载。**合并进 `lk1337.ko` 后的版本尚未在设备上复测**：功能代码逐行保留，但加载路径、bootstrap 入口和 hook 注册策略都变了，需要重新验证。

## 进程隐藏控制器（prochide）

`prochide/` 是进程隐藏功能的用户态控制器：单文件 C、无第三方依赖，直接按 [memwatch_uapi.h](memwatch_uapi.h) 的 ABI 发命令。它通过 `MW_BOOTSTRAP` 拿到 lk1337 的匿名会话 fd，再发 `641` 至 `645`。

> 该目录已被 `.gitignore` 忽略，只保留在本地工作区，不随仓库分发。

```sh
make -C prochide          # 静态 arm64：prochide/prochide-arm64（NDK r29，默认 API 21）
make -C prochide host     # 本机编译检查（连不上模块，但 list 可用）
adb push prochide/prochide-arm64 /data/local/tmp/prochide
adb shell su -c /data/local/tmp/prochide query
```

| 命令 | 作用 |
| --- | --- |
| `add <pid\|name\|self>...` | 隐藏进程；按名字会隐藏所有匹配项 |
| `remove <pid\|name\|self>...` | 取消隐藏 |
| `clear` | 清空隐藏列表 |
| `enable [flag...]` / `disable` | 启用 / 停用隐藏，flag 为 `proc`、`lookup`、`signal`、`hideroot`（默认 `proc lookup signal`） |
| `query` / `status` | 显示 enabled、flags 和已隐藏 PID |
| `list <pid\|name>` | 只读 `/proc` 列出匹配进程，用来确认名字 |
| `watch <pid\|name> [-i 秒] [-f flag,...] [--keep]` | 常驻，目标重启后自动重新隐藏 |
| 无参数 | 交互模式（`watch` 不在此模式运行） |

命名匹配是**精确匹配**，`comm`、`argv[0]` 的 basename、可执行文件 basename 三者之一相等即命中；`self` 表示调用者自己的线程组。`-q` 抑制正常输出，错误始终走 stderr，退出码 0 成功 / 1 有失败项。

`watch` 的语义（每轮与 `MW_HIDE_QUERY` 对账）：

- **只管理自己添加的 PID**：别的会话已隐藏的条目不碰，退出时也不会替它取消；`--keep` 表示退出时保留自己的条目。
- 记录每个 PID 的 `/proc/<pid>/stat` starttime。PID 被回收给别的进程后 starttime 变化会被识别并取消隐藏，避免误伤无关进程。
- 每轮确认隐藏仍启用且 flags 与请求一致，否则重新 `enable`。
- 名字目标跟随名字：目标重启（新 PID）后会被重新隐藏，watch 一直运行到 Ctrl-C。
- PID 目标跟随该 PID 的那一次进程生命周期：目标退出或被回收后 watch 停止，不会去隐藏顶替该 PID 的新进程。
- 用了 `hideroot` 时 root 也读不到隐藏进程，`/proc` 无法确认目标存活：此时信任模块列表中的条目（已隐藏且读不到 `/proc` 就不清理），PID 回收检测在这一档失效。

## TTBR 线程内存视图分离

目标：同一个进程内按线程选择内存视图——**executor 线程看原始 source 视图，同进程其他线程看 alter 视图**。命令 `630` 创建、`631` 更新 alter 内容、`632`/`633` 设置/清除 executor、`634` 销毁、`635` 查询。

实测（`prochide/ttbrsplit.c`）：主线程作为 executor，另起一个 reader 线程读同一地址，executor 读到 `'A'`（source），reader 读到 `'B'`（alter），且 reader 在 alter 视图下写的一个私有全局变量 executor 也能看到——证明除目标范围外两个视图是**真正共享**的。

### 按线程选 TTBR 是怎么接进去的

上一版卡在调度切换：`ttbr_view.c` 里 `finish_task_switch` 的实现被 `#if 0` 掉，注释指出在 rq lock 下调 `check_and_switch_context()` 会死锁。现在的做法是**完全不碰 ASID 管理**：

1. 两个视图用**同一个 ASID**——就是 source mm 自己的。内核把它放在 TTBR1_EL1 里（`TCR.A1=1` 时 TTBR1 的 ASID 是权威的），我们只替换 TTBR0_EL1 的翻译基址，ASID 字段原样保留。所以不需要 `new_context()`、不需要 `cpu_asid_lock`、没有任何可能睡眠的操作。
2. 切换点选在 **`__schedule()` 的 post_handler**（`current` 已经是调度进来的任务）。`__schedule` 每次调度都会执行，包括同一个任务被重新选中的情况；`finish_task_switch` 只在真的换了任务时执行。视图安装只是写 `TTBR0_EL1` + `isb`，在 rq lock 下安全。
3. **软件 PAN 与硬件 PAN 都覆盖**：本设备 CPU 有硬件 PAN，`system_uses_ttbr0_pan()` 为假，内核在 `cpu_do_switch_mm()` 里直接编程 TTBR0、返回用户态时（KPTI 的 exit trampoline 只改 TTBR1）**不会重载** TTBR0，所以必须自己写硬件寄存器；同时软件 PAN 下 `__uaccess_ttbr0_enable()` 会从 `thread_info->ttbr0` 重载，所以那份缓存副本也一起写。
4. **TLB 一致性**：两个视图同 ASID，所以一条被某个视图缓存的表项对另一个视图同样"有效"却可能指向错误内容。每 CPU 记录当前安装的 pgd 物理地址，视图真正变化时用 `__tlbi(aside1)` + `__tlbi_user(aside1)` 做**本地** ASID 失效（本内核没有 `local_flush_tlb_mm()`，这两个宏自己写）。KPTI 下用户态表项带 `USER_ASID_FLAG`，`__tlbi_user` 已覆盖。

### alter 视图为什么必须共享页表

第一版沿用 `dup_mm()`/`dup_mmap()` 克隆出一个 mm，再把目标范围的 PTE 换成自己的页。**这是错的**：alter 视图下发生缺页时，内核用的仍然是 `current->mm`（source mm），修正会被写进 **source** 的页表，alter 的页表永远填不上——reader 第一次写自己的 COW 栈就会陷入无限缺页（实测现象：进程 `state=R`、`stime` 疯涨、reader 永不返回）。

现在 `alter` 不是 mm，而是一个**我们自己分配的 pgd 页**：除目标范围所在的 pgd 项外，全部直接拷贝 source 的 pgd 项（**共享**下层的 pmd/pte 表）；目标范围那一个 pgd 项换成私有的 pmd 表（1 GB 粒度），其中一个 pmd 项再换成私有的 pte 表（2 MB 粒度），只把这一个（或连续几个）PTE 指向我们自己的页。这样：

- 任何缺页修正都落在两个视图共享的表里，双方都看得到；
- setup 之后新映射的内存（新 `mmap`、栈增长、堆扩展）在两个视图里都可见；
- 除了目标范围，两个视图的页表**完全相同**，非 executor 线程可以正常跑（实测 reader 写私有全局变量 executor 可见）。

目标 mm 只用 `get_task_mm()` 取一次，然后 `mmgrab()` 换成 `mm_count` 引用再 `mmput()`：`struct mm_struct` 不会消失（指针可安全比较），但进程退出时 `exit_mmap()` 仍会正常执行，不会把整个地址空间钉住。executor 退出时 `do_exit` 钩子把该 split 退役（`active=false`）——否则进程里所有线程都会开始看 alter 视图，而 alter 里目标范围是伪造内容。

### 默认方向：executor 看 alter，其它线程看原版

**默认就是"executor 线程看 alter 视图、进程里其它线程看原版页表"**——这是常见用例需要的方向：
只让一个线程跑在被改过的内容上（比如 inline hook），进程其余部分完全不受影响。

`LK1337_TTBR_SETUP` 的 `LK1337_TTBR_F_EXECUTOR_SOURCE` 反向选择旧行为：executor 保持原版，
其它线程看 alter（"进程整体跑在沙箱里、控制线程在外面"）。`LK1337_TTBR_QUERY` 读回的 `flags` 会带回实际生效的方向。

> **兼容性**：ABI 5 里的 `LK1337_TTBR_F_EXECUTOR_ALTER` 位已经作废，传入会被**明确拒绝（`-EINVAL`）**而不是
> 当成空操作——旧调用方传这一位是想要"翻转默认值"，而在新默认下它恰好就是默认值，静默忽略会把它
> 带到相反的方向。ABI 已升到 6。实测见 `prochide/flagcheck.c`：

```
obsolete EXECUTOR_ALTER bit: ret=-1 errno=22 (Invalid argument)
EXECUTOR_SOURCE bit:        ret=0 errno=0 (Success)
PASS: obsolete bit rejected, new bit accepted
```

实现上热路径只多一个判断（`is_executor == split->executor_alter` 时选 alter，否则选原版 `mm->pgd`），
并且安装路径不再用 `NULL` 当"executor"的哨兵，而是显式传入要装的那张页表——翻转后两个方向都要写
TTBR0，哨兵写法会让 executor 那一支变成空操作。

实测（`prochide/ttbrflip.c`，不传任何 flag 即默认方向；父进程当 executor、子进程建立 split 并作为"其它线程"）：

```
executor(parent) sees 0x42 ('B')   non-executor(child) sees 0x41 ('A')
executor's store was contained: shared alter page still 0x42 ('B')
after teardown executor sees 0x5a ('Z')
PASS: executor saw the alter view, other threads kept the original
```

四点语义需要明确：

1. **视图由 `__schedule` post-handler 选定，所以调用线程必须先经过一次上下文切换**才会看到新视图。
   测试里 executor 在读取前 `sched_yield()` 几十次就是这个原因——刚建好就立刻读，本 CPU 可能还没切换过。
2. **alter 侧的 PTE 是 `PAGE_READONLY`**，executor 往目标范围写会触发保护性缺页，按 COW 的方式解析成
   私有副本，**不会**改到共享的 alter 页（实测：写完共享 alter 页仍是 `0x42`）。也就是说 executor 对目标
   范围的写入被"关在自己视图里"，这通常是想要的，但要注意它不是普通可写映射。
3. **销毁 split 后 executor 仍留在 alter 视图**：`ttbr_force_source()` 会显式把 executor 放回 alter 页
   （`EXECUTOR_SOURCE` 方向则放回原版页表），否则拆掉 split 之后就再没有东西替它选视图了。
4. 目标范围之外的页表项仍然与源进程共享，所以两个视图在别处保持一致；只有目标范围是私有的。

### 用例：让 inline hook 只对被指定线程生效

这是翻转方向最直接的用法——把"打补丁"变成"改翻译"，于是 hook 只存在于一个线程的视图里：

```
源进程的代码页（真实内容）:  mov w0, #1 ; ret      ← 其它线程执行这条，返回 1
alter 页（模块私有）:        mov w0, #2 ; ret      ← executor 执行这条，返回 2
```

真实代码页**从头到尾没有被写过**，所以任何检查代码校验和、`/proc/self/mem`、`ptrace` 读取、
或者直接跑一遍这段代码的检测手段，看到的都是未修改的原始指令；只有被指定的那个线程运行在 hook 后的
指令流上。这与普通 inline hook（写 `br` 跳板）的区别就在这里：普通 hook 是全局且可被校验和发现的。

实测（`prochide/tthook.c`，父进程是 executor、子进程建立 split 并作为"其它线程"）：

```
executor (parent) return = 2   (2 == hooked stream)
other    (child)  return = 1   (1 == original stream)
PASS: executor ran the inline-hooked stream, other threads ran the original, source page untouched
```

#### 三个必须处理的细节

1. **split 范围要覆盖整个页。** alter 视图只对自己范围内的 PTE 做私有拷贝，范围之外的页表项与源进程
   共享——所以"只替换页面里某几条指令"必须按整页设置范围，不能只圈住被改的那几个字节所在的页表项。
2. **装好视图后必须刷 I-cache。** 改 PTE 不会让 I-cache 失效，CPU 可能继续执行它**先前从原始页取到的**
   指令，即使同一地址的数据读取已经返回 hook 后的内容。实测：不刷 I-cache 时"读到的字是 hook 的、执行
   结果却还是原版的"。用户态用 `ic ivau` + `dsb ish` + `isb` 即可（设备 `SCTLR_EL1.UCI=1`，实测有效），
   见 `prochide/icache_flush.h`。
3. **executor 要先经过一次上下文切换。** 视图由 `__schedule` post-handler 选定，刚建好 split 就立刻
   执行本 CPU 可能还停在旧视图上。

#### 限制

- 目标是**页粒度**的：hook 只对整页生效，页内其它指令也走 alter 版本。
- alter 侧 PTE 是只读的，executor 对目标范围的写入会被解析成私有副本，不会落到共享 alter 页，
  也不会影响源进程——通常正是想要的。
- 这与"隐藏"是两件事：本页对其它线程而言完全正常（内容一致），不一致只体现在 executor 的翻译上。

### 限制与取舍

- **目标范围必须是 PTE 级映射**：2 MB 块映射要覆盖其中一页就得先拆分块，当前直接返回 `-EOPNOTSUPP`。
- **TTBR 单次范围限制为一个 2 MB PMD**：范围必须完全落在同一个 PMD 内；跨 PMD 的视图需要拆成多个视图（当前实现不接受跨界范围）。
- **私有 pmd 表是 setup 时刻 source pmd 表项的拷贝**：这些表项指向 source 的 pte 表（所以是共享的），但如果 setup 之后在**目标所属的那个 1 GB 区间内**新建了一个 2 MB 页表（该 pmd 项从"无"变成"指向新 pte 表"），alter 侧不会自动看到。目标区间之外（其他 pgd 项）不受影响。
- 两个视图**同 ASID**，所以每次视图切换都要本地失效一次 ASID，代价比独立 ASID 高；换来的是完全不需要碰内核的 ASID 分配器。
- 只对 **64 位**线程生效，目标必须是 source mm 的线程（`executor_tid` 不属于该 mm 时返回 `-EXDEV`）。
- 改的是页表而不是数据：`alter_mem` 里的内容会被复制进模块自己的页，之后调整内容要用 `631` 更新。

## kprobe 延迟与按需注册

模块的探针不再在 `lk1337_init()` 里一次性全部注册。每条探针都由 `probe_mgr.h` 按引用计数管理：
只有真正使用某个功能时才把探针装进内核，最后一个使用者退出时立刻摘掉。空闲（已加载但未使用任何功能）
的模块在内核里**没有功能探针**。

### 为什么必须这样做

一个常驻 kprobe 不是免费的。本机实测（`bench/`）单次 kprobe 命中给目标函数增加约 **200–500 ns**，
而模块原来常驻 11 条探针，其中 `__schedule` 是**全系统每一次上下文切换**都要走的路径。这条开销恰好
是无特权进程唯一可以在不依赖 SELinux 的情况下测到的足迹：配对系统调用时延差分既不需要 root，也不需要
debugfs 或内核地址。实测对照（identity 类告警无法消除，见下）：

| 配对 | 模块未加载 | 旧实现（常驻） | 现在（空闲） |
| --- | --- | --- | --- |
| `sendto` vs `recvfrom` | 1.00x | **2.13x** | **1.00x** |
| `sched_yield` vs `sched_getaffinity` | 1.07x | **1.89x** | **1.12x** |
| 无特权探测器总告警数 | 0 | 5 | **2**（都只是 `/proc/modules`、`/sys/module`） |

### 各探针的注册时机

| 探针 | 目标 | 何时安装 / 摘除 |
| --- | --- | --- |
| bootstrap | `inet_ioctl` | 模块生命周期级（唯一常驻的一条，见下） |
| gyro | `__arm64_sys_sendto` | 第一次 `LK1337_GYRO_CONFIG` 打开时；关闭时摘除 |
| UXN（4 条） | `exit_mmap`、`__arm64_sys_mprotect`、`__arm64_sys_pkey_mprotect`、`change_protection` | 第一个 UXN 断点建立时；最后一个回收时摘除 |
| TTBR（3 条） | `__schedule`、`do_exit`、`begin_new_exec` | 第一个视图建立时；最后一个销毁时摘除 |
| maps 过滤 | `show_map_vma` 等 | 原本就是懒加载，第一次配置规则时注册 |
| 进程隐藏（3 条） | `proc_fill_cache`、`proc_pid_lookup`、`do_send_sig_info` | 第一次配置隐藏时；`MW_HIDE_QUERY` 只回答实际生效的 hook |

`exit_mmap` 钩子里不能直接摘探针（kprobe pre-handler 里不允许取可睡眠锁），回收计数通过 task_work 延后处理。

bootstrap 是唯一的例外：每个新客户端都要重新取一次会话 fd，一条“用过就摘掉”的探针会让第二个客户端
再也进不来。它常驻的代价有界——handler 只比较一个寄存器就返回，配对差分约 1.1x，实测未触发告警。
这里量到 1.12x，作为对照，`sched_yield` 那条被修掉的通道原本是 1.89x。

### 两个必须绕开的 kprobe 语义陷阱

1. **`unregister_kprobe()` 会在调用方结构体里留下旧地址**。直接重新 `register_kprobe()` 同一个结构体会被
   `check_kprobe_rereg()` 以 `-EINVAL` 拒绝，探针静默地永远回不来。因此每次注册前都要 `memset` 整个结构体。
2. **模块卸载时处于 disabled 状态的探针不会被内核清理**。核心的 module notifier 只遍历未 `kprobe_gone()`
   的条目；被留下来的是指向已释放模块内存的哈希项，之后同一地址的 `register_kprobe()` 一律 `-EINVAL`
   （实测表现：卸载再加载后所有探针都注册失败）。因此本模块只让探针处于“完全注册”或“完全注销”两种状态，
   绝不留下 disable 状态。

> 顺带修掉一个崩溃级缺陷：非 root 调用 bootstrap 命令时，pre-handler 只写返回值、没有写 `regs->pc`。
> 本内核的 arm64 kprobe 在 pre_handler 返回非 0 时既不单步也不推进 PC，于是 `inet_ioctl` 首指令的 BRK 被
> 无限重放——实测 5 秒约 2500 万次回调，进程永不返回、`SIGKILL` 无效、一个 CPU 核直到重启都收不回。
> 现在会写入 `regs->pc = regs->regs[30]` 并返回 `-ENOTTY`。

### 显形修复：`ioctl(602)` 可写私有匿名页

写权限判据原来用 `pte_write()`。arm64 上 `PTE_WRITE` 就是 `PTE_DBM`（bit 51），私有可写页只有在硬件
AF/DBM 生效时才带这一位，其余情况可写性由 `AP[2]` 表达（`PTE_RDONLY` 清零）。结果是共享映射能写、
而调试最需要的 `.bss`/`.data`/堆/JIT 页一律 `-EFAULT`。判据改为
`pte_write(entry) || !(pte_val(entry) & PTE_RDONLY)`，实测同一进程的私有匿名缓冲区写入成功。

### 空闲态的残余：模块身份

按需注册之后，**空闲模块的运行时可观测面已经归零**：没有功能探针、时延通道全部回到基线、`ru_minflt`
干净、页表无异常。剩下的只有"模块存在"这件事本身，而无特权可见的身份面有三层：

| 面 | uid 2000 实测 | 说明 |
| --- | --- | --- |
| `/proc/modules` | 列出 `lk1337` | 名字本身不可避免（除非做 rootkit 式摘链，代价是模块无法卸载） |
| `/sys/module/lk1337` | 目录存在，`coresize` 泄漏模块大小 | 同上 |
| `/proc/kallsyms` | **1125 行 / 843 个符号名** | 这是信息量最大的一个：符号名几乎写出了功能清单 |

第三层是本次新发现的。kallsyms 会发布模块携带的每个符号，所以未处理的 `.ko` 会把
`lk1337_uxn_fault`、`lk1337_ttbr_build_alter_tables`、`mw_proc_fill_cache_pre` 这样的名字全盘列出
——攻击者不需要任何测量就能读出"这个模块有 UXN 断点、TTBR 视图分离、进程隐藏"。

构建现在在链接后自动 `llvm-strip --strip-unneeded`（见 `Makefile` 的 `STRIP` 步骤）：

```
1125 行 / 843 个不同符号名   →   101 行 / 101 个
```

省下的 91% 是编译器产物（`.LtmpN`、`$x.N`）和大部分静态函数名。仍会泄漏的是约 50 个**有描述性的
静态函数名**（`lk1337_probe_mgr_init`、`lk1337_uxn_fault$<hash>`、`lk1337_memwatch_dispatch`、
`ttbr_schedule_post$<hash>` 等）以及 CFI 跳转表项 `名字.cfi_jt`——重命名这 50 个函数可以进一步抹掉，
但需要同步改动大量宏引用，尚未做。

> 关于威胁模型：真实的 `untrusted_app` 域通常被 SELinux 拒绝读取 `/proc/modules`、`/sys/module/*`
> 和 `/proc/kallsyms`，所以这三层在生产环境里的可达性取决于设备策略；但它们不需要任何时序测量，
> 一旦可读就是确定性的。

### 进程隐藏能挡到什么程度

进程隐藏只过滤 procfs 视图和信号投递，内核任务表不变。实测 16 个"给定 pid 是否存在"的系统调用
（`bench/oracle.c`）对同一个隐藏 pid **全部照常解析**：`sched_getscheduler`、`pidfd_open`、`getpriority`、
`prlimit64`、`getpgid`、`kcmp`、`process_vm_readv`、`ptrace(PTRACE_ATTACH)` 等。
其中 `kill(pid, 0)` 特别值得注意的是它**根本不经过** `do_send_sig_info`（信号 0 不投递），所以那个钩子
对它无效。

因此：

- 挂钩 `sched_getscheduler`/`pidfd_open` 解决不了探测——同类原语有十几个入口，堵两个换第三个即可；
- 要彻底封闭得让所有 pid 型系统调用对隐藏 pid 返回 `-ESRCH`，而 `ptrace`/`process_vm_readv` 是正常调试
  接口，改了会破坏系统；
- **唯一有效的是顺序**：在探测方建立基线之前完成隐藏。差分需要"先看见、后消失"，一开始就不可见的 pid
  不会产生不一致。

### 哪些功能会造成 syscall 时序不一致

不是所有挂钩都会产生时序差分——**只有挂钩在"高频函数"上、且存在同形状的对照 syscall 时才成立**。
逐功能实测（同一台机器、同一配对方法，模块从未加载作为基线）：

| 状态 | 被挂钩的函数 | 配对差分实测 | 会被时序探测吗 |
| --- | --- | --- | --- |
| 未加载 | — | `sendto/recvfrom` 1.00x、`inet/unix` 0.99~1.07x、`yield/affin` 1.17x | 否 |
| 已加载空闲 | 仅 bootstrap（`inet_ioctl.cfi_jt`） | 全部 1.00x 量级 | 否（该函数 30 秒 0 次自然调用） |
| 仅 UXN 断点 | `exit_mmap`、`__arm64_sys_mprotect`、`pkey_mprotect`、`change_protection` | `sendto/recvfrom` 1.00x、`inet/unix` 1.09x、`yield/affin` 1.17x —— **无差分** | 否（探针只在这些冷路径上） |
| 仅 gyro | `__arm64_sys_sendto` | `sendto/recvfrom` **2.22x**（490 vs 221 ns，+269 ns） | **是，最强** |
| 仅 TTBR 视图 | `__schedule`、`do_exit`、`begin_new_exec` | `yield/affin` 跳到 **2.0~2.75x**（+230~960 ns） | **是**（`__schedule` 每次上下文切换都走） |
| 仅进程隐藏 | `proc_fill_cache`、`proc_pid_lookup`、`do_send_sig_info` | 三组配对全部 1.00x —— **无差分** | 否（procfs 每项成本压倒钩子，见下） |
| maps 过滤 | `show_map_vma`、`show_smap*`、`map_files_*` | 无差分（只在读 maps 时触发） | 否 |

结论：

1. **`__schedule` 是最响的那条**——它是唯一"每次上下文切换都要走"的挂点，所以任何触发调度的 syscall
   （`sched_yield`、`nanosleep`、`futex`、以及一切阻塞操作）都会变慢，用 `sched_getaffinity` 这种
   "同类别但不调度"的 syscall 做对照就能自校准地量出来。这就是原来 1.89x 的来源，也是按需注册后
   受益最大的一条。
2. **`sendto` 是第二响的**，因为它本身就是热系统调用，而 `recvfrom` 是同形状对照。
3. **UXN 和进程隐藏没有时序面**：它们的挂钩都在冷路径（`mprotect`、`exit_mmap`、procfs 目录项），
   而且 procfs 有自己的每项成本（实测 `proc` 约 2.5 µs/项 vs `dev` 约 0.16 µs/项），钩子的 ~200 ns
   完全被淹没。这两类功能只能靠**逻辑不一致**探测（UXN 吞吐自校准、列表差分），不是时序。
4. 因此"按需注册"这个改动的价值集中在 **`__schedule`（TTBR）和 `sendto`（gyro）** 两条：不用这两个功能
   时它们不在内核里，时序面就是零。

### TTBR 视图切换的热路径改成无锁

`__schedule` 的 post_handler 每次上下文切换都要为 `current->mm` 找 split。原来它在**每 CPU 每次切换**上取一把
全局 raw spinlock 再遍历链表。在调度密集型负载下插桩实测：**单个 CPU 上约 1700 万次 post-handler 调用**，
而这段代码还持有 runqueue lock——8 个核全部在这把锁上串行。

现在热路径完全无锁：

- 增加一个 `ttbr_active_split` 指针，只在建立/销毁（进程上下文）时写入，热路径 `rcu_dereference` 读取；
- 每个 mm 最多一个 split，所以单指针足够，不需要遍历；
- 销毁时先 `rcu_assign_pointer(NULL)` 再用 `synchronize_rcu()` 等所有在途读者退出，之后才释放——读者不可能
  解引用已释放的 split。

无锁化后功能回归仍然通过（executor 看 source、其他线程看 alter、UXN、bootstrap 全部 PASS，无 oops/CFI/panic）。

### 关于压力测试中的看门狗重启

压测 TTBR 视图（`ttbrstress-arm64` 让 `sched_yield` 满速跑 45 秒 + `lkarm --keep` 长驻 split）时观察到过几次
设备重启。证据与结论：

- 复位原因可从启动参数读出：`aee_aed.pureason=Watchdog`、`poffreason=Cold_reset`，且 pstore 控制台日志在
  重启前**没有任何** oops/panic/lockup 打印——所以是硬挂起（watchdog 复位），不是内核崩溃；
- 本内核**没有** `CONFIG_HARDLOCKUP_DETECTOR`，且 `hung_task_timeout_secs=0`，所以中断关闭状态下的硬挂起
  必然是静默的；硬件 watchdog 带 `nowayout` 且 `sysrq=0`，无法关掉它换取一次完整 backtrace；
- 为找根因做了对照实验：**无模块**跑同样的 yield 风暴（6700 万次 `sched_yield`）存活；**有模块但无 split**
  （8430 万次）存活；**建立 split 并启用视图安装**后曾多次复位；
- 但把安装路径禁用、以及把热路径改成无锁之后，**受控 A/B 都没能再复现**：基线（有锁）5 次跑 4 次存活、
  无锁版 3 次存活，两者在同样的轮次遇到同一次 adb 掉线。也就是说这几次复位**无法用现有手段稳定复现**，
  根因**尚未确定**，无锁化是独立的改进而不是已验证的修复。

复现脚本都在 `bench/`：`repro2.sh` 会先校验"模块真的加载了、split 真的建立了"再压测，避免把失败配置算成一次
存活；`ttbrstress.c` 是对应的负载进程。受控 A/B 的结果是**有锁版 4/5 存活、无锁版 3/3 存活**，两者在同一轮次
遇到同一次 adb 掉线——所以结论是"目前无法稳定复现"，而不是"已修复"。

### 测量工具

| 文件 | 作用 |
| --- | --- |
| `bench/kprobe_bench.c` | 装载多个探针并统计命中次数，证明 `finish_task_switch` 这类静态函数仍可挂钩 |
| `bench/abbench.c` | 同一台机器、同一次开机下对比探针开/关时的系统调用时延 |
| `bench/ioctlcmp.c` | `inet` 与 `unix` ioctl 路径的对照测量 |
| `bench/verify.sh` | 端到端验证：bootstrap×3、非 root 行为、UXN/大页/边缘/mprotect、TTBR、探针装卸日志 |
| `prochide/lkdetect.c` | 无特权探测器；时延配对采用**双向交替测量取较小值**，消除“先测的一侧承担预热开销”偏差 |

## 源码布局

| 文件 | 职责 |
| --- | --- |
| `entry.c` | 模块生命周期、bootstrap、会话与 ioctl 分发 |
| `debugger_uapi.h` | 用户态 ABI、命令和结构体 |
| `memory.h` / `process.h` | 内存传输与映射查询 |
| `hw_breakpoint.h` | perf 断点、命中记录和修改模板 |
| `uxn_breakpoint.h` | 页表 UXN 执行断点：`fault_info[]` 接管、fixmap 只读写入、PTE/PMD 陷阱、单步与 task_work 重新武装 |
| `fpsimd_state.h` / `fpsimd_state.S` | ARM64 FPSIMD/SVE 状态辅助 |
| `maps_filter.h` | proc 映射信息过滤（含 CFI 改名符号解析） |
| `probe_mgr.h` | kprobe 按引用计数按需注册/注销；实现只在 `entry.c` 实例化一次 |
| `ttbr_view.c` / `ttbr_view.h` | 线程级 TTBR 视图分离 |
| `memwatch.c` / `memwatch.h` / `memwatch_uapi.h` | 进程隐藏实现、对 `entry.c` 的接口、用户态 ABI；编入 `lk1337.ko` |
| `bench/` | 探针开销与功能回归的测量工具（见上） |
| `prochide/` | 进程隐藏控制器（用户态 CLI + `watch`），自带 Makefile |
| `.gitignore` | 忽略模块构建产物、`prochide/` 和 `mwtest/`：用户态工具与设备工件只保留在本地 |
| `cfi_bypass.h` / `comm.h` | 当前构建未引用的辅助代码 |
| `log_test.c` | 独立日志诊断模块源码，未加入默认构建 |

`Makefile` 当前链接 `entry.o`、`fpsimd_state.o`、`ttbr_view.o` 和 `memwatch.o`。因此模块构建仍不能验证未被引用的 `cfi_bypass.h`：其中的页权限修改不等于绕过 CFI，相关内核 API 的导出情况、权限恢复和并发写入行为仍需单独验证。

`mwtest/` 目录保存设备测试期留下的工件，不参与构建，同 `prochide/` 一起被 `.gitignore` 忽略：`mwctl.c` 是早期最小控制工具，功能已被 `prochide/` 取代（两者都通过 `MW_BOOTSTRAP` 打开 fd，可互换使用）；合并前独立 `memwatch.ko` 的设备副本已从仓库删除，需要回退时按合并前的提交重新构建。
