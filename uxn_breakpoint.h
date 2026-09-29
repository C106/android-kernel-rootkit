/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LK1337_UXN_BREAKPOINT_H
#define LK1337_UXN_BREAKPOINT_H

/*
 * Page-table backed execution breakpoints for lk1337.
 *
 * A perf hardware breakpoint is limited by the number of BRP registers the CPU
 * implements (typically 4-6) and is per-thread. This backend emulates an
 * execution breakpoint with a page-table permission trap instead:
 *
 *   1. the PTE (or block PMD) of the mapping holding the target address gets
 *      PTE_UXN (execute never for EL0), so the next EL0 instruction fetch from
 *      that mapping takes an instruction abort (ESR_ELx_EC_IABT_LOW, FSC =
 *      permission fault);
 *   2. the abort is taken over at the kernel's fault dispatch: the entries of
 *      fault_info[] that point at do_page_fault() are replaced with
 *      lk1337_uxn_fault(). For a fault in a mapping this feature owns the
 *      handler records a hit (when the faulting PC matches a registered
 *      address), clears PTE_UXN and arms a hardware single step, then reports
 *      the fault as handled so no signal is delivered and the instruction
 *      re-executes;
 *   3. the software-step exception is claimed by a user step hook, and a
 *      task_work callback re-arms PTE_UXN before user code resumes.
 *
 * Taking over fault_info[] instead of probing the page-fault slow path matters:
 *
 *   - it intercepts the abort *before* anything else looks at it, so mappings
 *     whose faults never reach handle_mm_fault() work too. Anonymous executable
 *     mappings (JIT) are exactly that case on kernels with the Android
 *     speculative page fault patch, which consumes a present-PTE fault inside
 *     handle_pte_fault() and would otherwise turn the trap into an unhandled
 *     fault loop.
 *   - the handler runs in process context (do_mem_abort() is entered with
 *     interrupts and preemption enabled), so it may sleep.
 *
 * fault_info[] is const .rodata and, on this GKI layout, sits in a 2 MB block
 * mapping of the kernel image, which has no linear-map alias (map_mem() marks
 * the image NOMAP). Neither set_memory_rw() (it insists on a VM_ALLOC vmalloc
 * area) nor a temporary vmap() alias (it oopsed on the target device) works.
 * The write therefore reuses the kernel's own text-poke trick: a temporary
 * fixmap mapping of the page, obtained through __set_fixmap(), written with a
 * single aligned 64-bit store so no CPU can observe a torn function pointer.
 * The vendor kernel's __set_fixmap() does not flush the TLB on the set path,
 * so the flush is done explicitly here.
 *
 * CFI: do_mem_abort() calls the table entry through a CFI-checked indirect
 * call. lk1337_uxn_fault() is declared with the exact fault_info prototype and
 * made addressable with __CFI_ADDRESSABLE() so the module reports a type hash
 * the core kernel's __cfi_slowpath()/module __cfi_check() accepts.
 */

#include <linux/cfi.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/task_work.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/debug-monitors.h>
#include <asm/esr.h>
#include <asm/fixmap.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "probe_mgr.h"

struct lk1337_uxn_restore {
	struct callback_head callback;
	unsigned int count;	/* granules retired by this work item */
};
static void lk1337_uxn_drop_hooks_workfn(struct callback_head *callback);

/* Mirror of arch/arm64/mm/fault.c:struct fault_info. */
struct lk1337_fault_info {
	int (*fn)(unsigned long far, unsigned int esr, struct pt_regs *regs);
	int sig;
	int code;
	const char *name;
};

/* One registered execution breakpoint in a mapping granule. */
struct lk1337_uxn_ref {
	struct list_head node;
	struct lk1337_uxn_page *page;
	struct lk1337_breakpoint *bp;
	unsigned long addr;
	bool paused;
};

/* One mapping granule (4 KB page, or a block PMD) this feature controls. */
struct lk1337_uxn_page {
	struct list_head node;
	struct list_head refs;
	struct mm_struct *mm;		/* identity token, valid until exit_mmap */
	unsigned long base;		/* granule aligned base address */
	unsigned int shift;		/* PAGE_SHIFT or PMD_SHIFT */
	bool uxn_set;			/* mapping currently carries our PTE_UXN */
	bool restore_queued;		/* a protection change is being handled */
	pid_t stepping_tid;		/* task that must re-arm after a step */
};

#define LK1337_UXN_FSC_MAX 64

static LIST_HEAD(lk1337_uxn_pages);
/* Raw spinlock: taken from the fault handler and from the atomic single-step
 * hook, both of which run with preemption disabled. */
static DEFINE_RAW_SPINLOCK(lk1337_uxn_lock);

/* fault_info[] replacement state. */
static struct lk1337_fault_info *lk1337_uxn_fault_info;
static int (*lk1337_uxn_orig[LK1337_UXN_FSC_MAX])(unsigned long, unsigned int,
						   struct pt_regs *);
static unsigned int lk1337_uxn_slots[LK1337_UXN_FSC_MAX];
static unsigned int lk1337_uxn_nslots;
static bool lk1337_uxn_faults_hooked;

/* Resolved kernel helpers (none of these are exported to modules). */
static unsigned long (*lk1337_uxn_lookup_name)(const char *name);
static void (*lk1337_uxn_register_step_hook)(struct step_hook *hook);
static void (*lk1337_uxn_unregister_step_hook)(struct step_hook *hook);
static void (*lk1337_uxn_step_enable)(struct task_struct *task);
static void (*lk1337_uxn_step_disable)(struct task_struct *task);
typedef void (*lk1337_set_fixmap_t)(enum fixed_addresses, phys_addr_t, pgprot_t);
static lk1337_set_fixmap_t lk1337_uxn_set_fixmap;
static raw_spinlock_t *lk1337_uxn_patch_lock;

typedef int (*lk1337_uxn_task_work_add_t)(struct task_struct *,
					  struct callback_head *,
					  enum task_work_notify_mode);
static lk1337_uxn_task_work_add_t lk1337_uxn_task_work_add;

static int lk1337_uxn_fault(unsigned long far, unsigned int esr,
			    struct pt_regs *regs);
static void *lk1337_uxn_symbol(const char *name);
static void lk1337_uxn_restore_workfn(struct callback_head *callback);
static int lk1337_uxn_protect(struct mm_struct *mm, unsigned long addr,
			      bool nx, unsigned long *base_out,
			      unsigned int *shift_out, bool *was_set_out);

/*
 * Every call through a runtime-resolved pointer goes through a __nocfi
 * wrapper: the target is reached by address, and clang's CFI check at a plain
 * indirect call site in this module rejects it. The one exception is
 * lk1337_uxn_fault() itself, which must stay type-visible for the *kernel's*
 * check (see __CFI_ADDRESSABLE below).
 */
static __nocfi unsigned long lk1337_uxn_call_lookup(const char *name)
{
	return lk1337_uxn_lookup_name(name);
}

static __nocfi void lk1337_uxn_call_register_step(struct step_hook *hook)
{
	lk1337_uxn_register_step_hook(hook);
}

static __nocfi void lk1337_uxn_call_unregister_step(struct step_hook *hook)
{
	lk1337_uxn_unregister_step_hook(hook);
}

static __nocfi void lk1337_uxn_call_step_enable(struct task_struct *task)
{
	lk1337_uxn_step_enable(task);
}

static __nocfi void lk1337_uxn_call_step_disable(struct task_struct *task)
{
	lk1337_uxn_step_disable(task);
}

static __nocfi int lk1337_uxn_call_task_work_add(struct task_struct *task,
						 struct callback_head *work,
						 enum task_work_notify_mode mode)
{
	return lk1337_uxn_task_work_add(task, work, mode);
}

static __nocfi void lk1337_uxn_call_set_fixmap(enum fixed_addresses idx,
					       phys_addr_t phys, pgprot_t prot)
{
	lk1337_uxn_set_fixmap(idx, phys, prot);
}

static __nocfi int lk1337_uxn_call_orig(int (*orig)(unsigned long, unsigned int,
						    struct pt_regs *),
					unsigned long far, unsigned int esr,
					struct pt_regs *regs)
{
	return orig(far, esr, regs);
}

static struct lk1337_uxn_page *lk1337_uxn_find_page(struct mm_struct *mm,
						    unsigned long base)
{
	struct lk1337_uxn_page *entry;

	list_for_each_entry(entry, &lk1337_uxn_pages, node)
		if (entry->mm == mm && entry->base == base)
			return entry;
	return NULL;
}

static bool lk1337_uxn_page_wants_uxn(struct lk1337_uxn_page *page)
{
	struct lk1337_uxn_ref *ref;

	list_for_each_entry(ref, &page->refs, node)
		if (!ref->paused)
			return true;
	return false;
}

/* ------------------------------------------------------------------ */
/* Writing kernel image read-only memory                               */
/* ------------------------------------------------------------------ */

/*
 * Replace one aligned 64-bit word of kernel image memory through a temporary
 * fixmap alias of its page. FIX_TEXT_POKE0 is shared with kprobes, so the
 * kernel's own patch_lock serialises the two users.
 *
 * The physical address comes from __pa_symbol() (i.e. addr - kimage_voffset),
 * NOT from virt_to_page(): with CONFIG_SPARSEMEM_VMEMMAP and no
 * CONFIG_DEBUG_VIRTUAL, arm64's virt_to_page() derives the struct page from
 * the linear-map offset, which is meaningless for the kernel image (it has no
 * linear mapping at all). Using it maps an arbitrary physical page and the
 * store then corrupts memory.
 */
static int lk1337_uxn_poke64(void *dst, u64 value)
{
	unsigned long addr = (unsigned long)dst;
	unsigned long offset = addr & ~PAGE_MASK;
	unsigned long fixmap_va, flags;
	phys_addr_t phys = __pa_symbol(addr);

	if (!lk1337_uxn_set_fixmap || !lk1337_uxn_patch_lock)
		return -EOPNOTSUPP;
	if (!IS_ALIGNED(addr, sizeof(value)) ||
	    offset + sizeof(value) > PAGE_SIZE)
		return -EINVAL;
	if (!pfn_valid(__phys_to_pfn(phys))) {
		pr_warn("UXN: refusing to poke non-RAM address %px\n", dst);
		return -EFAULT;
	}

	fixmap_va = __fix_to_virt(FIX_TEXT_POKE0);
	raw_spin_lock_irqsave(lk1337_uxn_patch_lock, flags);
	lk1337_uxn_call_set_fixmap(FIX_TEXT_POKE0, phys, FIXMAP_PAGE_NORMAL);
	/* This kernel's __set_fixmap() only flushes on the clear path. */
	flush_tlb_kernel_range(fixmap_va, fixmap_va + PAGE_SIZE);
	/* One aligned 64-bit store: no CPU can observe a torn pointer. */
	WRITE_ONCE(*(u64 *)(fixmap_va + offset), value);
	dsb(ish);
	lk1337_uxn_call_set_fixmap(FIX_TEXT_POKE0, 0, __pgprot(0));
	raw_spin_unlock_irqrestore(lk1337_uxn_patch_lock, flags);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Taking over the permission-fault dispatch                           */
/* ------------------------------------------------------------------ */

/*
 * The permission-fault entries. fault_info[] is indexed by the ESR FSC field,
 * which is architectural: 0x0D/0x0E/0x0F are "permission fault, level 1/2/3".
 * Slots are addressed by index rather than by comparing .fn against the
 * kallsyms address of do_page_fault(), because with CFI the table holds the
 * function's jump-table entry while kallsyms reports the function body.
 */
static const unsigned int lk1337_uxn_perm_slots[] = { 13, 14, 15 };

static int lk1337_uxn_hook_faults(void)
{
	void *do_page_fault, *do_bad;
	unsigned int i, n = 0;

	if (lk1337_uxn_faults_hooked)
		return 0;
	if (!lk1337_uxn_fault_info)
		return -EOPNOTSUPP;

	do_page_fault = lk1337_uxn_symbol("do_page_fault");
	do_bad = lk1337_uxn_symbol("do_bad");

	for (i = 0; i < ARRAY_SIZE(lk1337_uxn_perm_slots); i++) {
		unsigned int slot = lk1337_uxn_perm_slots[i];
		int (*fn)(unsigned long, unsigned int, struct pt_regs *) =
			READ_ONCE(lk1337_uxn_fault_info[slot].fn);

		if (!fn) {
			pr_warn("UXN: fault_info[%u] empty\n", slot);
			continue;
		}
		pr_info("UXN: slot %u fn=%px name=%s (do_page_fault=%px do_bad=%px)\n",
			slot, fn, lk1337_uxn_fault_info[slot].name,
			do_page_fault, do_bad);
		lk1337_uxn_orig[slot] = fn;
		lk1337_uxn_slots[n++] = slot;
	}
	if (!n) {
		pr_warn("UXN: no permission-fault slot available\n");
		return -ENOENT;
	}

	for (i = 0; i < n; i++) {
		u64 value = (u64)(uintptr_t)lk1337_uxn_fault;
		void *slot = &lk1337_uxn_fault_info[lk1337_uxn_slots[i]].fn;

		if (lk1337_uxn_poke64(slot, value))
			goto rollback;
	}
	lk1337_uxn_nslots = n;
	lk1337_uxn_faults_hooked = true;
	pr_info("UXN: took over %u permission-fault slot(s), handler=%px\n",
		n, lk1337_uxn_fault);
	return 0;

rollback:
	while (i--) {
		u64 value = (u64)(uintptr_t)
			lk1337_uxn_orig[lk1337_uxn_slots[i]];
		void *slot = &lk1337_uxn_fault_info[lk1337_uxn_slots[i]].fn;

		lk1337_uxn_poke64(slot, value);
	}
	pr_err("UXN: failed to install fault handler, rolled back\n");
	return -EIO;
}

static void lk1337_uxn_unhook_faults(void)
{
	unsigned int i;

	if (!lk1337_uxn_faults_hooked)
		return;
	for (i = 0; i < lk1337_uxn_nslots; i++) {
		u64 value = (u64)(uintptr_t)
			lk1337_uxn_orig[lk1337_uxn_slots[i]];
		void *slot = &lk1337_uxn_fault_info[lk1337_uxn_slots[i]].fn;

		lk1337_uxn_poke64(slot, value);
	}
	lk1337_uxn_faults_hooked = false;
	lk1337_uxn_nslots = 0;
	pr_info("UXN: fault dispatch restored\n");
}

/*
 * Entry point installed into fault_info[]. The prototype must match
 * struct fault_info::fn exactly for the kernel's CFI check to accept it.
 * __CFI_ADDRESSABLE guarantees the module's jump table carries it.
 */
static int lk1337_uxn_fault(unsigned long far, unsigned int esr,
			    struct pt_regs *regs)
{
	unsigned int fsc = esr & ESR_ELx_FSC;
	int (*orig)(unsigned long, unsigned int, struct pt_regs *);
	struct lk1337_uxn_page *page;
	struct lk1337_uxn_ref *ref;
	struct lk1337_breakpoint *bp = NULL;
	unsigned long lock_flags, base = 0, addr, hit_addr = 0;
	/*
	 * Fault accounting. Returning 0 from do_mem_abort() means do_page_fault()
	 * -> handle_mm_fault() -> mm_account_fault() never runs, so our traps do
	 * not show up in getrusage(2)/minflt, /proc/<pid>/stat or the
	 * PERF_COUNT_SW_PAGE_FAULTS software event -- which is what the earlier
	 * handle_mm_fault-based backend leaked (measured +827 minor faults for
	 * 100 trapped calls). The counter is saved and restored on the paths we
	 * handle ourselves as an explicit guarantee against a kernel whose
	 * dispatch accounts the fault somewhere else. Delegated faults keep their
	 * accounting, since those are genuine.
	 */
	unsigned long min_flt_saved = current->min_flt;
	pid_t tid;
	bool ours = false;

	orig = (fsc < LK1337_UXN_FSC_MAX) ? lk1337_uxn_orig[fsc] : NULL;
	if (!orig)
		return 0;

	if (!user_mode(regs) || ESR_ELx_EC(esr) != ESR_ELx_EC_IABT_LOW)
		return lk1337_uxn_call_orig(orig, far, esr, regs);

	/* For an instruction abort FAR is the faulting PC. */
	addr = untagged_addr(far);
	tid = task_pid_vnr(current);

	raw_spin_lock_irqsave(&lk1337_uxn_lock, lock_flags);
	list_for_each_entry(page, &lk1337_uxn_pages, node) {
		if (page->mm != current->mm)
			continue;
		if ((addr >> page->shift) != (page->base >> page->shift))
			continue;
		if (!page->uxn_set)
			break;	/* not our trap: a genuine permission fault */
		list_for_each_entry(ref, &page->refs, node)
			if (ref->addr == addr && !ref->paused && !bp) {
				bp = ref->bp;
				hit_addr = ref->addr;
			}
		base = page->base;
		page->uxn_set = false;
		page->stepping_tid = tid;
		ours = true;
		/* Safe here: UXN rejects LK1337_BP_F_BACKTRACE, so recording a
		 * hit never sleeps, and the breakpoint cannot be freed while the
		 * global lock is held. */
		if (bp)
			lk1337_handle_hit(bp, regs, hit_addr);
		break;
	}
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, lock_flags);

	if (!ours) {
		bool stray = false;

		/*
		 * Safety net. A UXN bit left on an executable mapping we no
		 * longer track (mremap moved the entry, something rewrote it
		 * behind our back) makes the original handler report the abort
		 * as handled, so the instruction would re-execute forever.
		 * Detect exactly that shape and clear it. lk1337_uxn_protect()
		 * refuses non-executable VMAs, so genuine execution faults on a
		 * non-executable mapping still take the normal SIGSEGV path.
		 */
		lk1337_uxn_protect(current->mm, addr, false, NULL, NULL, &stray);
		if (stray) {
			pr_info_ratelimited("UXN: cleared stray UXN at %lx\n", addr);
			current->min_flt = min_flt_saved;
			return 0;
		}
		return lk1337_uxn_call_orig(orig, far, esr, regs);
	}

	/* Process context: may take mmap_read_lock. */
	lk1337_uxn_protect(current->mm, base, false, NULL, NULL, NULL);
	if (lk1337_uxn_step_enable)
		lk1337_uxn_call_step_enable(current);
	else
		set_thread_flag(TIF_SINGLESTEP);
	/* Handled entirely by us: leave the task's fault counters untouched. */
	current->min_flt = min_flt_saved;
	return 0;
}

__CFI_ADDRESSABLE(lk1337_uxn_fault);

/* ------------------------------------------------------------------ */
/* PTE / block PMD manipulation                                        */
/* ------------------------------------------------------------------ */

/*
 * Set or clear PTE_UXN on the mapping granule containing @addr for @mm.
 * Handles both a 4 KB PTE and a block PMD. On success @base_out/@shift_out
 * report the granule that was actually modified, so the caller can match
 * faults at the same granularity. Takes mmap_read_lock itself.
 */
static int lk1337_uxn_protect(struct mm_struct *mm, unsigned long addr, bool nx,
			      unsigned long *base_out, unsigned int *shift_out,
			      bool *was_set_out)
{
	struct vm_area_struct *vma;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pmd_t middle;
	spinlock_t *ptl;
	pte_t *ptep;
	pte_t entry, updated;
	unsigned long base = addr & PAGE_MASK;
	unsigned int shift = PAGE_SHIFT;
	bool was_set = false;
	int error = 0;

	if (!mm)
		return -EINVAL;
	mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start) {
		error = -ENOENT;
		goto out;
	}
	/* The trap only means anything on an executable mapping. */
	if (!(vma->vm_flags & VM_EXEC)) {
		error = -EACCES;
		goto out;
	}
	pgd = pgd_offset(mm, addr);
	if (pgd_none(READ_ONCE(*pgd)) || pgd_bad(READ_ONCE(*pgd))) {
		error = -EFAULT;
		goto out;
	}
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(READ_ONCE(*p4d)) || p4d_bad(READ_ONCE(*p4d))) {
		error = -EFAULT;
		goto out;
	}
	pud = pud_offset(p4d, addr);
	if (pud_none(READ_ONCE(*pud)) || pud_bad(READ_ONCE(*pud)) ||
	    pud_sect(READ_ONCE(*pud))) {
		error = -EFAULT;
		goto out;
	}
	pmd = pmd_offset(pud, addr);
	middle = READ_ONCE(*pmd);
	/*
	 * Test for a block mapping before pmd_bad(): on arm64 pmd_bad() is
	 * "not a table", which is true for a valid block PMD, so the usual
	 * none/bad/present order would reject every huge page.
	 */
	if (pmd_trans_huge(middle) || pmd_sect(middle)) {
		/* Block mapping: the UXN bit lives in the PMD and the trap
		 * covers the whole 2 MB granule. */
		pmd_t changed;

		base = addr & PMD_MASK;
		shift = PMD_SHIFT;
		ptl = pmd_lock(mm, pmd);
		middle = READ_ONCE(*pmd);
		was_set = (pmd_val(middle) & PTE_UXN) != 0;
		changed = nx ? __pmd(pmd_val(middle) | PTE_UXN)
			     : __pmd(pmd_val(middle) & ~PTE_UXN);
		if (pmd_val(changed) != pmd_val(middle))
			set_pmd(pmd, changed);
		spin_unlock(ptl);
		/* flush_tlb_page() invalidates only the last level; a block
		 * entry needs an all-levels, ASID-wide invalidation. */
		flush_tlb_mm(mm);
		goto out;
	}
	if (pmd_none(middle) || pmd_bad(middle) || !pmd_present(middle)) {
		error = -EFAULT;
		goto out;
	}
	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	entry = READ_ONCE(*ptep);
	if (!pte_present(entry) || pte_protnone(entry)) {
		error = -EFAULT;
		goto unlock;
	}
	was_set = (pte_val(entry) & PTE_UXN) != 0;
	updated = nx ? __pte(pte_val(entry) | PTE_UXN)
		     : __pte(pte_val(entry) & ~PTE_UXN);
	/* set_pte_at() would pull in __sync_icache_dcache() and mte_sync_tags(),
	 * which are not exported. Only the execute permission changes here, so
	 * neither the instruction cache nor the MTE tags need resynchronising;
	 * set_pte() plus the TLB maintenance below is sufficient. */
	if (pte_val(updated) != pte_val(entry))
		set_pte(ptep, updated);
	pte_unmap_unlock(ptep, ptl);
	flush_tlb_page(vma, addr);
	goto out;

unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	mmap_read_unlock(mm);
	if (!error) {
		if (base_out)
			*base_out = base;
		if (shift_out)
			*shift_out = shift;
		if (was_set_out)
			*was_set_out = was_set;
	}
	return error;
}

/*
 * Bring one UXN granule in line with its desired state, identified by (mm,
 * base) rather than by pointer: the entry can be reclaimed by the exit_mmap
 * hook between two lock acquisitions. Must be called without lk1337_uxn_lock.
 */
static void lk1337_uxn_sync(struct mm_struct *mm, unsigned long base)
{
	struct lk1337_uxn_page *page;
	bool want, have;
	unsigned long flags;

	raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
	page = lk1337_uxn_find_page(mm, base);
	if (!page) {
		raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
		return;
	}
	want = lk1337_uxn_page_wants_uxn(page);
	have = page->uxn_set;
	if (want != have)
		page->uxn_set = want;
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
	if (want == have)
		return;
	if (lk1337_uxn_protect(mm, base, want, NULL, NULL, NULL)) {
		raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
		page = lk1337_uxn_find_page(mm, base);
		if (page)
			page->uxn_set = have;
		raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
		pr_warn_ratelimited("UXN: failed to %s mapping %lx\n",
				    want ? "protect" : "release", base);
	}
}

/* ------------------------------------------------------------------ */
/* Single-step completion: re-arm the trap                             */
/* ------------------------------------------------------------------ */

struct lk1337_uxn_rearm {
	struct callback_head callback;
};

/* Runs from exit_to_user_mode_loop(): process context, safe to sleep. */
static void lk1337_uxn_rearm_workfn(struct callback_head *callback)
{
	struct lk1337_uxn_page *page;
	unsigned long flags;
	unsigned int guard = 0;

	for (;;) {
		unsigned long target = 0;

		raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
		list_for_each_entry(page, &lk1337_uxn_pages, node) {
			if (page->mm != current->mm || page->uxn_set ||
			    !lk1337_uxn_page_wants_uxn(page))
				continue;
			target = page->base;
			break;
		}
		raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
		if (!target || ++guard > 64)
			break;
		if (lk1337_uxn_protect(current->mm, target, true, NULL, NULL, NULL))
			break;
		raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
		list_for_each_entry(page, &lk1337_uxn_pages, node)
			if (page->mm == current->mm && page->base == target)
				page->uxn_set = true;
		raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
	}
	kfree(container_of(callback, struct lk1337_uxn_rearm, callback));
}

/*
 * Claim the software-step exception raised after a UXN trap. Returns
 * DBG_HOOK_HANDLED so single_step_handler() neither delivers SIGTRAP nor
 * rewinds the step; the mapping is re-armed from a task_work callback because
 * this hook runs with preemption disabled.
 */
static int lk1337_uxn_step_fn(struct pt_regs *regs, unsigned int esr)
{
	struct lk1337_uxn_page *page;
	struct lk1337_uxn_rearm *work;
	unsigned long flags;
	pid_t tid = task_pid_vnr(current);
	bool ours = false;

	if (!user_mode(regs))
		return DBG_HOOK_ERROR;

	raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
	list_for_each_entry(page, &lk1337_uxn_pages, node) {
		if (page->mm == current->mm && page->stepping_tid == tid) {
			page->stepping_tid = 0;
			ours = true;
		}
	}
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
	if (!ours)
		return DBG_HOOK_ERROR;

	regs->pstate &= ~DBG_SPSR_SS;
	if (lk1337_uxn_step_disable)
		lk1337_uxn_call_step_disable(current);
	else
		clear_thread_flag(TIF_SINGLESTEP);

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return DBG_HOOK_HANDLED;
	work->callback.func = lk1337_uxn_rearm_workfn;
	if (!lk1337_uxn_task_work_add ||
	    lk1337_uxn_call_task_work_add(current, &work->callback, TWA_RESUME))
		kfree(work);
	return DBG_HOOK_HANDLED;
}

static struct step_hook lk1337_uxn_step_hook = { .fn = lk1337_uxn_step_fn };

/* ------------------------------------------------------------------ */
/* Surviving protection changes (mprotect)                             */
/* ------------------------------------------------------------------ */

/*
 * A protection change rewrites the affected PTEs/PMDs, which drops our
 * PTE_UXN and would silently disarm the breakpoint.
 *
 * Tracking the exact range is not portable: the helper that performs the
 * rewrite differs between trees, and on the target device change_protection()
 * is never reached at all (the vendor kernel's mprotect path calls something
 * else), so a probe there never fires. Instead the entry points simply queue a
 * verification pass for current->mm on the next return to user mode, and the
 * worker re-applies PTE_UXN to every granule that should be armed.
 * lk1337_uxn_protect() is idempotent, so re-arming an already armed granule is
 * harmless, and the pass costs nothing when the mm has no breakpoints.
 *
 * These run as kprobe pre-handlers, i.e. with preemption disabled, hence the
 * task_work: the worker runs in process context once the syscall has released
 * mmap_write_lock, which is what makes taking mmap_read_lock legal there.
 */
static int lk1337_uxn_queue_restore(void)
{
	struct lk1337_uxn_page *page;
	struct lk1337_uxn_restore *work;
	unsigned long flags;
	bool need = false;

	if (!current->mm)
		return 0;

	raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
	list_for_each_entry(page, &lk1337_uxn_pages, node) {
		if (page->mm != current->mm || page->restore_queued)
			continue;
		page->restore_queued = true;
		need = true;
	}
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
	if (!need)
		return 0;

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		goto clear;
	work->callback.func = lk1337_uxn_restore_workfn;
	if (!lk1337_uxn_task_work_add ||
	    lk1337_uxn_call_task_work_add(current, &work->callback, TWA_RESUME)) {
		kfree(work);
		goto clear;
	}
	return 0;

clear:
	raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
	list_for_each_entry(page, &lk1337_uxn_pages, node)
		if (page->mm == current->mm)
			page->restore_queued = false;
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
	return 0;
}

static int lk1337_uxn_change_prot_pre(struct kprobe *probe, struct pt_regs *regs)
{
	return lk1337_uxn_queue_restore();
}

static int lk1337_uxn_mprotect_pre(struct kprobe *probe, struct pt_regs *regs)
{
	return lk1337_uxn_queue_restore();
}

static int lk1337_uxn_pkey_mprotect_pre(struct kprobe *probe,
					struct pt_regs *regs)
{
	return lk1337_uxn_queue_restore();
}

/*
 * Protection-change hooks, installed only while at least one UXN granule is
 * armed.  LK1337_UXN_HOOKS is what the refcount below toggles.
 */
static struct lk1337_probe lk1337_uxn_change_prot_probe =
	LK1337_PROBE("change_protection", "uxn", lk1337_uxn_change_prot_pre, NULL);
static struct lk1337_probe lk1337_uxn_mprotect_probe =
	LK1337_PROBE("__arm64_sys_mprotect", "uxn", lk1337_uxn_mprotect_pre, NULL);
static struct lk1337_probe lk1337_uxn_pkey_mprotect_probe =
	LK1337_PROBE("__arm64_sys_pkey_mprotect", "uxn",
		     lk1337_uxn_pkey_mprotect_pre, NULL);

/* Process context: re-assert PTE_UXN on every granule that should be armed. */
static void lk1337_uxn_restore_workfn(struct callback_head *callback)
{
	struct lk1337_uxn_page *page;
	unsigned long flags;
	unsigned int guard = 0;

	kfree(container_of(callback, struct lk1337_uxn_restore, callback));

	for (;;) {
		unsigned long base = 0;
		bool did = false;

		raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
		list_for_each_entry(page, &lk1337_uxn_pages, node) {
			if (page->mm != current->mm || !page->restore_queued)
				continue;
			page->restore_queued = false;
			did = true;
			if (lk1337_uxn_page_wants_uxn(page)) {
				base = page->base;
				page->uxn_set = true;
			}
			break;
		}
		raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
		if (!did || ++guard > 64)
			break;
		if (!base)
			continue;
		if (lk1337_uxn_protect(current->mm, base, true, NULL, NULL, NULL)) {
			raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
			page = lk1337_uxn_find_page(current->mm, base);
			if (page)
				page->uxn_set = false;
			raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
		}
	}
}

/* ------------------------------------------------------------------ */
/* Process teardown                                                    */
/* ------------------------------------------------------------------ */

/*
 * The target's mm is going away: drop every granule that belongs to it. The
 * page tables are torn down right after this, so nothing is unprotected and no
 * lock that could sleep is taken (exit_mmap holds mmap_write_lock).
 */
static int lk1337_uxn_exit_mmap_pre(struct kprobe *probe, struct pt_regs *regs)
{
	struct mm_struct *mm = (struct mm_struct *)(uintptr_t)regs->regs[0];
	struct lk1337_uxn_page *page, *page_next;
	struct lk1337_uxn_ref *ref, *ref_next;
	unsigned long flags;
	unsigned int retired = 0;

	if (!mm)
		return 0;
	raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
	list_for_each_entry_safe(page, page_next, &lk1337_uxn_pages, node) {
		if (page->mm != mm)
			continue;
		retired++;
		list_del(&page->node);
		list_for_each_entry_safe(ref, ref_next, &page->refs, node) {
			list_del(&ref->node);
			if (ref->bp)
				ref->bp->uxn_ref = NULL;
			kfree(ref);
		}
		kfree(page);
	}
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
	if (retired) {
		struct lk1337_uxn_restore *work =
			kmalloc(sizeof(*work), GFP_ATOMIC);

		if (work) {
			work->count = retired;
			work->callback.func = lk1337_uxn_drop_hooks_workfn;
			if (!lk1337_uxn_task_work_add ||
			    lk1337_uxn_call_task_work_add(current, &work->callback,
							  TWA_RESUME))
				kfree(work);
		}
	}
	return 0;
}

static struct lk1337_probe lk1337_uxn_exit_mmap_probe =
	LK1337_PROBE("exit_mmap", "uxn", lk1337_uxn_exit_mmap_pre, NULL);

/* Armed granules across all processes; the hooks exist only while this is > 0. */
static unsigned int lk1337_uxn_live_pages;
static DEFINE_MUTEX(lk1337_uxn_hooks_lock);

static void lk1337_uxn_hooks_arm(void)
{
	mutex_lock(&lk1337_uxn_hooks_lock);
	if (lk1337_uxn_live_pages++ > 0) {
		mutex_unlock(&lk1337_uxn_hooks_lock);
		return;
	}
	/*
	 * Each hook is optional.  A missing one only degrades a specific
	 * recovery path (mprotect re-arm, mm teardown); the breakpoint itself
	 * still works, so failures are not fatal.
	 */
	if (lk1337_probe_use(&lk1337_uxn_exit_mmap_probe))
		pr_warn("UXN: exit_mmap hook unavailable, granules of exiting processes will leak\n");
	if (lk1337_probe_use(&lk1337_uxn_mprotect_probe))
		pr_warn("UXN: mprotect hook unavailable, mprotect will disarm a breakpoint\n");
	if (lk1337_probe_use(&lk1337_uxn_pkey_mprotect_probe))
		pr_debug("UXN: pkey_mprotect hook unavailable\n");
	if (lk1337_probe_use(&lk1337_uxn_change_prot_probe))
		pr_debug("UXN: change_protection hook unavailable\n");
	mutex_unlock(&lk1337_uxn_hooks_lock);
}

static void lk1337_uxn_hooks_disarm(void)
{
	mutex_lock(&lk1337_uxn_hooks_lock);
	if (lk1337_uxn_live_pages == 0 || --lk1337_uxn_live_pages > 0) {
		mutex_unlock(&lk1337_uxn_hooks_lock);
		return;
	}
	lk1337_probe_release(&lk1337_uxn_change_prot_probe);
	lk1337_probe_release(&lk1337_uxn_pkey_mprotect_probe);
	lk1337_probe_release(&lk1337_uxn_mprotect_probe);
	lk1337_probe_release(&lk1337_uxn_exit_mmap_probe);
	mutex_unlock(&lk1337_uxn_hooks_lock);
}

/* Drop @count granules at once (exit_mmap tears down a whole address space). */
static void lk1337_uxn_hooks_drop(unsigned int count)
{
	while (count--)
		lk1337_uxn_hooks_disarm();
}

/*
 * exit_mmap runs inside a kprobe pre-handler (preemption disabled), where
 * lk1337_uxn_hooks_drop() may not take its mutex.  The granule count is
 * therefore handed to task_work, which runs in process context once the syscall
 * is on its way back to userspace.
 */
static void lk1337_uxn_drop_hooks_workfn(struct callback_head *callback)
{
	struct lk1337_uxn_restore *work =
		container_of(callback, struct lk1337_uxn_restore, callback);

	lk1337_uxn_hooks_drop(work->count);
	kfree(work);
}

static void lk1337_uxn_hooks_arm(void);
static void lk1337_uxn_hooks_disarm(void);
static void lk1337_uxn_hooks_drop(unsigned int count);

/* ------------------------------------------------------------------ */
/* Session interface                                                   */
/* ------------------------------------------------------------------ */

static int lk1337_uxn_create_bp(struct lk1337_session *session,
				struct lk1337_create *request)
{
	struct lk1337_breakpoint *bp;
	struct lk1337_uxn_page *page;
	struct lk1337_uxn_ref *ref;
	struct task_struct *task;
	struct pid *target;
	struct mm_struct *mm;
	unsigned long base = 0, flags;
	unsigned int shift = PAGE_SHIFT;
	bool hooks_armed = false;
	int error;

	if (request->type != 0 || request->len != 4 || (request->addr & 3) ||
	    !request->addr || request->addr >= TASK_SIZE_64 || request->pid < 0 ||
	    request->max_records < 0 || request->max_records > 4096 ||
	    (request->flags & ~(LK1337_BP_F_DETAIL | LK1337_BP_F_UXN)))
		return -EINVAL;
	/* UXN faults run under the raw breakpoint lock; the backtrace path is
	 * therefore not offered here even though perf uses in-atomic uaccess. */
	if (request->flags & LK1337_BP_F_BACKTRACE)
		return -EOPNOTSUPP;
	if (!lk1337_uxn_lookup_name || !lk1337_uxn_register_step_hook)
		return -EOPNOTSUPP;
	if (session->next_id == INT_MAX)
		return -ENOSPC;

	target = find_get_pid(request->pid ? request->pid : task_pid_vnr(current));
	if (!target)
		return -ESRCH;
	task = get_pid_task(target, PIDTYPE_PID);
	put_pid(target);
	if (!task)
		return -ESRCH;
	if (is_compat_thread(task_thread_info(task))) {
		put_task_struct(task);
		return -EOPNOTSUPP;
	}
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ESRCH;

	bp = kzalloc(sizeof(*bp), GFP_KERNEL);
	ref = kzalloc(sizeof(*ref), GFP_KERNEL);
	if (!bp || !ref) {
		error = -ENOMEM;
		goto out_free;
	}
	bp->capacity = request->max_records ? request->max_records : 256;
	bp->flags = request->flags;
	bp->uxn = true;
	bp->ring = kvcalloc(bp->capacity, sizeof(*bp->ring), GFP_KERNEL);
	if (!bp->ring) {
		error = -ENOMEM;
		goto out_free;
	}
	raw_spin_lock_init(&bp->lock);
	ref->bp = bp;
	ref->addr = request->addr;

	/* Arm first: this tells us which granule (page or block) we are on. */
	error = lk1337_uxn_protect(mm, request->addr, true, &base, &shift, NULL);
	if (error)
		goto out_free;

	raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
	page = lk1337_uxn_find_page(mm, base);
	if (!page) {
		page = kzalloc(sizeof(*page), GFP_KERNEL);
		if (!page) {
			raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
			error = -ENOMEM;
			goto out_disarm;
		}
		INIT_LIST_HEAD(&page->refs);
		page->mm = mm;
		page->base = base;
		page->shift = shift;
		list_add_tail(&page->node, &lk1337_uxn_pages);
	}
	ref->page = page;
	list_add_tail(&ref->node, &page->refs);
	page->uxn_set = true;
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
	/* First armed granule installs the mprotect/exit_mmap hooks. */
	lk1337_uxn_hooks_arm();
	hooks_armed = true;

	bp->uxn_ref = ref;
	bp->id = session->next_id++;
	list_add_tail(&bp->node, &session->breakpoints);
	request->bp_id = bp->id;
	mmput(mm);
	pr_info("UXN breakpoint id=%d addr=%lx pid=%d flags=0x%x granule=%s\n",
		bp->id, request->addr, request->pid, request->flags,
		shift == PMD_SHIFT ? "2M" : "4K");
	return 0;

out_disarm:
	lk1337_uxn_protect(mm, base, false, NULL, NULL, NULL);
	if (hooks_armed)
		lk1337_uxn_hooks_disarm();
out_free:
	if (bp)
		kvfree(bp->ring);
	kfree(ref);
	kfree(bp);
	mmput(mm);
	return error;
}

static void lk1337_uxn_destroy_bp(struct lk1337_breakpoint *bp)
{
	struct lk1337_uxn_ref *ref;
	struct lk1337_uxn_page *page;
	struct mm_struct *mm;
	unsigned long flags, base = 0;
	bool empty = false;

	raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
	ref = bp->uxn_ref;
	bp->uxn_ref = NULL;
	if (ref) {
		page = ref->page;
		mm = page->mm;
		base = page->base;
		list_del(&ref->node);
		empty = list_empty(&page->refs);
		if (empty)
			list_del(&page->node);
	}
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);

	if (!ref)
		return;
	if (empty) {
		lk1337_uxn_protect(mm, base, false, NULL, NULL, NULL);
		kfree(page);
		lk1337_uxn_hooks_disarm();
	} else {
		lk1337_uxn_sync(mm, base);
	}
	kfree(ref);
}

static int lk1337_uxn_set_enabled(struct lk1337_breakpoint *bp, bool enable)
{
	struct lk1337_uxn_ref *ref;
	struct mm_struct *mm;
	unsigned long flags, base;

	raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
	ref = bp->uxn_ref;
	if (ref) {
		mm = ref->page->mm;
		base = ref->page->base;
		ref->paused = !enable;
	}
	raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
	if (!ref)
		return -ENOENT;
	lk1337_uxn_sync(mm, base);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void lk1337_uxn_resolve_kallsyms(void)
{
	struct kprobe probe = { .symbol_name = "kallsyms_lookup_name" };

	if (!register_kprobe(&probe)) {
		lk1337_uxn_lookup_name =
			(unsigned long (*)(const char *))probe.addr;
		unregister_kprobe(&probe);
	}
}

static void *lk1337_uxn_symbol(const char *name)
{
	if (!lk1337_uxn_lookup_name)
		return NULL;
	return (void *)lk1337_uxn_call_lookup(name);
}

static int lk1337_uxn_init(lk1337_uxn_task_work_add_t task_work_add)
{
	int error;

	lk1337_uxn_task_work_add = task_work_add;
	lk1337_uxn_resolve_kallsyms();
	if (!lk1337_uxn_lookup_name) {
		pr_warn("UXN: kallsyms_lookup_name unavailable, feature disabled\n");
		return -ENOENT;
	}

	lk1337_uxn_fault_info =
		(struct lk1337_fault_info *)lk1337_uxn_symbol("fault_info");
	lk1337_uxn_set_fixmap = lk1337_uxn_symbol("__set_fixmap");
	lk1337_uxn_patch_lock = lk1337_uxn_symbol("patch_lock");
	lk1337_uxn_register_step_hook =
		lk1337_uxn_symbol("register_user_step_hook");
	lk1337_uxn_unregister_step_hook =
		lk1337_uxn_symbol("unregister_user_step_hook");
	lk1337_uxn_step_enable = lk1337_uxn_symbol("user_enable_single_step");
	lk1337_uxn_step_disable = lk1337_uxn_symbol("user_disable_single_step");

	if (!lk1337_uxn_register_step_hook) {
		pr_warn("UXN: register_user_step_hook unavailable, feature disabled\n");
		return -ENOENT;
	}
	if (!lk1337_uxn_task_work_add) {
		pr_warn("UXN: task_work_add unavailable, feature disabled\n");
		return -ENOENT;
	}

	error = lk1337_uxn_hook_faults();
	if (error)
		return error;

	lk1337_uxn_call_register_step(&lk1337_uxn_step_hook);

	/*
	 * No kprobe is installed here.  The mprotect and exit_mmap hooks exist
	 * only while at least one granule is armed (see lk1337_uxn_hooks_arm),
	 * so an idle module has no probe in the kernel at all.
	 */
	pr_info("UXN execution breakpoints ready (hooks installed on demand)\n");
	return 0;
}

static void lk1337_uxn_exit(void)
{
	/* Return every hook reference this feature still holds. */
	while (lk1337_uxn_live_pages)
		lk1337_uxn_hooks_disarm();
	if (lk1337_uxn_unregister_step_hook)
		lk1337_uxn_call_unregister_step(&lk1337_uxn_step_hook);
	lk1337_uxn_unhook_faults();

	/* Sessions are released before this runs, so normally nothing is left;
	 * release anything that is. */
	for (;;) {
		struct lk1337_uxn_page *page;
		struct lk1337_uxn_ref *ref, *ref_next;
		unsigned long flags, base;
		struct mm_struct *mm;

		raw_spin_lock_irqsave(&lk1337_uxn_lock, flags);
		page = list_first_entry_or_null(&lk1337_uxn_pages,
						struct lk1337_uxn_page, node);
		if (!page) {
			raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);
			break;
		}
		list_del(&page->node);
		mm = page->mm;
		base = page->base;
		list_for_each_entry(ref, &page->refs, node)
			ref->bp->uxn_ref = NULL;
		raw_spin_unlock_irqrestore(&lk1337_uxn_lock, flags);

		lk1337_uxn_protect(mm, base, false, NULL, NULL, NULL);
		list_for_each_entry_safe(ref, ref_next, &page->refs, node) {
			list_del(&ref->node);
			kfree(ref);
		}
		kfree(page);
	}
}

#endif /* LK1337_UXN_BREAKPOINT_H */
