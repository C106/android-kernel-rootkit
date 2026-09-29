# lk1337 ARM64 内核模块

面向 ARM64 Android GKI 5.10 的进程内存与硬件断点内核模块，构建产物为 `lk1337.ko`。

## 功能

- 进程内存读写与映射基址查询
- 基于 perf 的线程硬件断点和观察点
- 基于 PTE UXN 的执行断点
- 命中记录、寄存器模板和 FPSIMD 状态处理
- `/proc/<pid>/maps` 过滤
- system_server 陀螺仪数据调整
- 进程隐藏（memwatch）
- TTBR 线程级内存视图切换
- 按需注册和释放 kprobe

具体命令号、结构体和 ABI 定义见 [debugger_uapi.h](debugger_uapi.h) 与 [memwatch_uapi.h](memwatch_uapi.h)。

## 构建

依赖匹配目标设备的 ARM64 内核源码、内核输出目录和 Clang/LLVM 工具链。默认路径可在 `Makefile` 中查看或覆盖：

```sh
make modules
```

指定内核路径：

```sh
make modules \
  KDIR=/path/to/gki-5.10 \
  OUT=/path/to/kernel-out \
  CLANG_PREBUILT=/path/to/clang
```

清理构建产物：

```sh
make clean
```

模块依赖目标内核的符号版本和内部接口，不保证适配任意 ARM64 内核。

## 加载

在目标设备的 root shell 中执行：

```sh
insmod ./lk1337.ko
dmesg | tail -n 80
rmmod lk1337
```

模块通过 IPv4 socket 的 `inet_ioctl` 路径完成 bootstrap，不创建设备节点。客户端先发送 `LK1337_BOOTSTRAP` 获取匿名会话 fd，再通过该 fd 发送后续命令。bootstrap 和会话操作均要求 root。

## 主要接口

| 命令 | 用途 |
| --- | --- |
| `601`-`603` | 内存读写、映射基址查询 |
| `610`-`618` | 硬件/UXN 断点及命中记录 |
| `620` | 陀螺仪数据调整 |
| `621`-`628` | maps 过滤配置 |
| `630`-`635` | TTBR 内存视图 |
| `641`-`645` | 进程隐藏 |

接口参数以 UAPI 头文件为准。