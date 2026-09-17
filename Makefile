obj-m += lk1337.o
lk1337-objs := entry.o fpsimd_state.o ttbr_view.o

KDIR ?= $(HOME)/gki_clean/gki-5.10
OUT ?= $(KDIR)/out
ARCH ?= arm64
JOBS ?= 16
MODULE_DIR := $(CURDIR)
ccflags-y += -I$(KDIR)/fs/proc

CLANG_PREBUILT ?= $(KDIR)/../prebuilts/clang/host/linux-x86/clang-r416183b
LLVM ?= 1
LLVM_IAS ?= 1
CROSS_COMPILE ?= aarch64-linux-gnu-
export PATH := $(CLANG_PREBUILT)/bin:$(PATH)

MAKE_GKI = $(MAKE) -C $(KDIR) O=$(OUT) ARCH=$(ARCH) \
	LLVM=$(LLVM) LLVM_IAS=$(LLVM_IAS) \
	CROSS_COMPILE=$(CROSS_COMPILE)

.PHONY: all prepare kernel modules clean

all: modules

prepare:
	$(MAKE_GKI) gki_defconfig
	$(MAKE_GKI) olddefconfig
	$(MAKE_GKI) modules_prepare

modules:
	$(MAKE_GKI) M=$(MODULE_DIR) modules

kernel:
	$(MAKE_GKI) -j$(JOBS) vmlinux modules

clean:
	$(MAKE_GKI) M=$(MODULE_DIR) clean
