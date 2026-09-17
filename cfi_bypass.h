/* SPDX-License-Identifier: GPL-2.0 */
/* ARM64-only kernel-memory helpers for lk1337. */
#ifndef LK1337_CFI_BYPASS_H
#define LK1337_CFI_BYPASS_H

#if !defined(CONFIG_ARM64)
#error "lk1337/cfi_bypass.h requires an arm64 kernel"
#endif

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/set_memory.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

/* Resolve a non-exported symbol through the kprobe resolver. */
static inline unsigned long arm64_find_symbol(const char *name)
{
	struct kprobe probe = { .symbol_name = name };
	unsigned long address;

	if (!name || register_kprobe(&probe))
		return 0;
	address = (unsigned long)probe.addr;
	unregister_kprobe(&probe);
	return address;
}

static inline bool arm64_cfi_enabled(void)
{
#ifdef CONFIG_CFI_CLANG
	return true;
#else
	return false;
#endif
}

/* Verify that a complete range belongs to one writable vmalloc/module area. */
static inline int arm64_memory_range(const void *address, size_t length,
					unsigned long *start, int *pages)
{
	unsigned long first, last, size;
	struct vm_struct *area;

	if (!address || !length)
		return -EINVAL;
	first = (unsigned long)address & PAGE_MASK;
	if (length - 1 > ULONG_MAX - (unsigned long)address)
		return -EOVERFLOW;
	last = PAGE_ALIGN((unsigned long)address + length);
	if (last < first)
		return -EOVERFLOW;
	area = find_vm_area((void *)first);
	if (!area || !(area->flags & VM_ALLOC) ||
		last > (unsigned long)area->addr + area->size)
		return -EOPNOTSUPP;
	size = last - first;
	if (!size || size / PAGE_SIZE > INT_MAX)
		return -E2BIG;
	*start = first;
	*pages = (int)(size / PAGE_SIZE);
	return 0;
}

static DEFINE_MUTEX(arm64_memory_write_lock);

/* Write a vmalloc/module mapping and restore read-only page attributes. */
static inline int arm64_write_memory(void *destination, const void *source,
					size_t length)
{
	unsigned long start;
	int pages, ret, restore;

	if (!source || !destination || !length)
		return -EINVAL;
	ret = arm64_memory_range(destination, length, &start, &pages);
	if (ret)
		return ret;

	mutex_lock(&arm64_memory_write_lock);
	ret = set_memory_rw(start, pages);
	if (ret)
		goto out;
	ret = (int)copy_to_kernel_nofault(destination, source, length);
	if (!ret)
		flush_icache_range((unsigned long)destination,
				   (unsigned long)destination + length);
	restore = set_memory_ro(start, pages);
	if (!ret && restore)
		ret = restore;
out:
	mutex_unlock(&arm64_memory_write_lock);
	return ret;
}

static inline int arm64_write_ptr(void **destination, void *source)
{
	return arm64_write_memory(destination, &source, sizeof(source));
}

static inline int arm64_write_ulong(unsigned long *destination,
					unsigned long value)
{
	return arm64_write_memory(destination, &value, sizeof(value));
}

struct arm64_hook {
	void **target;
	void *original;
	void *replacement;
	bool installed;
};

static inline int arm64_install_hook(struct arm64_hook *hook)
{
	int ret;
	if (!hook || !hook->target || !hook->replacement)
		return -EINVAL;
	if (hook->installed)
		return -EALREADY;
	hook->original = READ_ONCE(*hook->target);
	ret = arm64_write_ptr(hook->target, hook->replacement);
	if (!ret)
		hook->installed = true;
	return ret;
}

static inline int arm64_remove_hook(struct arm64_hook *hook)
{
	int ret;
	if (!hook || !hook->target || !hook->installed)
		return -EINVAL;
	ret = arm64_write_ptr(hook->target, hook->original);
	if (!ret)
		hook->installed = false;
	return ret;
}

#ifdef DEBUG_CFI_BYPASS
#define arm64_cfi_debug(fmt, ...) pr_info("cfi-arm64: " fmt, ##__VA_ARGS__)
#else
#define arm64_cfi_debug(fmt, ...) do { } while (0)
#endif

static inline void arm64_dump_memory(const char *label, const void *address,
					     size_t length)
{
#ifdef DEBUG_CFI_BYPASS
	if (label && address && length)
		print_hex_dump(KERN_INFO, label, DUMP_PREFIX_OFFSET, 16, 1,
			       address, length, false);
#else
	(void)label;
	(void)address;
	(void)length;
#endif
}

static inline int arm64_cfi_init(void)
{
	arm64_cfi_debug("CFI enabled: %s\n",
			arm64_cfi_enabled() ? "yes" : "no");
	return 0;
}

static inline void arm64_cfi_exit(void)
{
	arm64_cfi_debug("shutdown\n");
}

/* Compatibility names retained for existing users of the old header. */
#define find_symbol_address arm64_find_symbol
#define is_cfi_enabled arm64_cfi_enabled
#define safe_memcpy arm64_write_memory
#define safe_write_ptr arm64_write_ptr
#define safe_write_ulong arm64_write_ulong
#define cfi_bypass_init arm64_cfi_init
#define cfi_bypass_exit arm64_cfi_exit
#define dump_memory arm64_dump_memory

struct hook_info {
	void **target_ptr;
	void *original_func;
	void *hook_func;
	bool hooked;
};

static inline int install_hook(struct hook_info *info)
{
	struct arm64_hook hook;
	if (!info)
		return -EINVAL;
	hook = (struct arm64_hook) {
		.target = info->target_ptr,
		.original = info->original_func,
		.replacement = info->hook_func,
		.installed = info->hooked,
	};
	if (arm64_install_hook(&hook))
		return -EFAULT;
	info->original_func = hook.original;
	info->hooked = true;
	return 0;
}

static inline int remove_hook(struct hook_info *info)
{
	struct arm64_hook hook;
	if (!info)
		return -EINVAL;
	hook = (struct arm64_hook) {
		.target = info->target_ptr,
		.original = info->original_func,
		.replacement = info->hook_func,
		.installed = info->hooked,
	};
	if (arm64_remove_hook(&hook))
		return -EFAULT;
	info->hooked = false;
	return 0;
}

#endif /* LK1337_CFI_BYPASS_H */
