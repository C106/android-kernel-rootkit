# `make` builds and then strips the module (see the `strip` target): kallsyms
# publishes every symbol a module carries, so an unstripped .ko hands an
# unprivileged reader the feature list in symbol-name form.
obj-m += lk1337.o
lk1337-objs := entry.o fpsimd_state.o ttbr_view.o memwatch.o

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

.PHONY: all prepare kernel modules strip clean

prepare:
	$(MAKE_GKI) gki_defconfig
	$(MAKE_GKI) olddefconfig
	$(MAKE_GKI) modules_prepare

modules:
	$(MAKE_GKI) M=$(MODULE_DIR) modules

# Always runs after a build, including incremental ones where the recursive
# make in `modules` does nothing: kprobes/make will not re-run a command just
# because the .ko still needs post-processing.
.PHONY: strip
strip:
	@# Drop the module's symbol table.  kallsyms publishes every symbol a
	@# module carries, so without this an unprivileged reader can read the
	@# feature list straight off the names (lk1337_uxn_*, lk1337_ttbr_*,
	@# memwatch_*: measured 1125 kallsyms lines / 843 distinct names, versus
	@# 101 after stripping).  The module still loads, resolves its own symbols
	@# and unloads normally -- the resolution the kernel needs lives in the
	@# .ko's ksymtab, not in .symtab.
	@if [ -f $(MODULE_DIR)/lk1337.ko ]; then \
		STRIP=$$(command -v llvm-strip || command -v $(CLANG_PREBUILT)/bin/llvm-strip); \
		if [ -n "$$STRIP" ] && [ -x "$$STRIP" ]; then \
			"$$STRIP" --strip-unneeded $(MODULE_DIR)/lk1337.ko && \
			echo "  STRIP   lk1337.ko"; \
		fi; \
	fi

all: modules strip

kernel:
	$(MAKE_GKI) -j$(JOBS) vmlinux modules
	$(MAKE) -C $(MODULE_DIR) strip

clean:
	$(MAKE_GKI) M=$(MODULE_DIR) clean
