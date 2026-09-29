#define pr_fmt(fmt) "lk1337-ttbr: " fmt

#include <linux/atomic.h>
#include <linux/highmem.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/pid.h>
#include <linux/refcount.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <asm/cacheflush.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>

#include "debugger_uapi.h"
#include "probe_mgr.h"
#include "ttbr_view.h"

struct lk1337_session {
	struct mutex lock;
	struct list_head breakpoints;
	struct list_head ttbr_views;
	void *memory_bounce;
	int next_id;
};

typedef unsigned long (*ttbr_kallsyms_lookup_name_t)(const char *);
typedef pte_t *(*ttbr_get_locked_pte_t)(struct mm_struct *, unsigned long,
							spinlock_t **);

static ttbr_kallsyms_lookup_name_t ttbr_kallsyms_lookup_name;
static ttbr_get_locked_pte_t ttbr_get_locked_pte;
static DEFINE_MUTEX(ttbr_global_lock);
static DEFINE_RAW_SPINLOCK(ttbr_split_lock);
static LIST_HEAD(ttbr_splits);
/*
 * The per-context-switch path needs to find the split for current->mm, and it
 * runs inside a kprobe post-handler with the runqueue lock held.  Scanning the
 * list under a global raw spinlock there meant every context switch on every
 * CPU serialised on one lock -- on an 8-core device under scheduler churn that
 * is millions of acquisitions per second per CPU, which is what wedged the box.
 *
 * Instead the hot path is lock-free: it reads this single pointer, which is
 * only ever set or cleared in process context (setup and teardown), and at most
 * one split exists per mm anyway.  Teardown waits for an RCU grace period
 * before freeing, so a reader can never dereference a freed split.
 *
 * Instrumentation of this path under scheduler churn measured ~17 million
 * post-handler invocations on a single CPU, each previously serialised on the
 * global lock while the runqueue lock was held.  That contention is worth
 * removing on its own; it is not proven to be the cause of the watchdog resets
 * seen while stress-testing view splits (see bench/ab_baseline.txt and
 * bench/ab_lockfree.txt -- both builds survived the same runs).
 */
static struct lk1337_ttbr_split __rcu *ttbr_active_split;
static atomic_t ttbr_next_id = ATOMIC_INIT(1);

struct lk1337_ttbr_split {
	struct list_head session_node;
	struct list_head global_node;
	struct mm_struct *source_mm;
	/*
	 * The alter view is a private pgd whose entries share the source mm's
	 * page-table pages, except for a private pmd+pte chain covering the
	 * target range.
	 */
	pgd_t *alter_pgd;
	pmd_t *alter_pmd;
	pte_t *alter_pte;
	unsigned int target_pgd_index;
	unsigned int target_pmd_index;
	struct page **real_pages;
	struct page **alter_pages;
	phys_addr_t *real_phys;
	phys_addr_t *alter_phys;
	unsigned long start;
	unsigned long end;
	/*
	 * True when the executor sees the alter view (the default) and every
	 * other thread sees the source view.
	 */
	bool executor_alter;
	unsigned int nr_pages;
	pid_t source_pid;
	pid_t executor_tid;
	struct mutex lock;
	refcount_t switch_refs;
	wait_queue_head_t switch_wait;
	bool active;
	int id;
};

/*
 * Which page table this feature installed last on each CPU, keyed by the
 * physical address of the pgd. Both views are walked with the *same* ASID (the
 * source mm's), so a view change on a CPU has to drop that CPU's translations
 * for the ASID; tracking the installed pgd lets us skip the flush when the
 * view did not actually change.
 */
static DEFINE_PER_CPU(unsigned long, ttbr_active_pgd);

static __nocfi __maybe_unused pte_t *ttbr_call_get_locked_pte(struct mm_struct *mm,
							unsigned long addr,
							spinlock_t **ptl)
{
	return ttbr_get_locked_pte(mm, addr, ptl);
}

static __nocfi unsigned long ttbr_call_kallsyms(const char *name)
{
	return ttbr_kallsyms_lookup_name(name);
}

static inline void ttbr_update_saved_ttbr0(struct task_struct *task,
						  struct mm_struct *mm)
{
#ifdef CONFIG_ARM64_SW_TTBR0_PAN
	u64 ttbr = phys_to_ttbr(virt_to_phys(mm->pgd)) | (ASID(mm) << 48);

	WRITE_ONCE(task_thread_info(task)->ttbr0, ttbr);
#else
	(void)task;
	(void)mm;
#endif
}

static int ttbr_resolve(void *storage, const char *name)
{
	struct kprobe probe = { .symbol_name = name };
	int ret;
	unsigned long address;

	ret = register_kprobe(&probe);
	if (!ret) {
		*(void **)storage = probe.addr;
		unregister_kprobe(&probe);
		return 0;
	}
	if (!ttbr_kallsyms_lookup_name)
		return ret;
	address = ttbr_call_kallsyms(name);
	if (!address)
		return ret;
	*(void **)storage = (void *)address;
	return 0;
}

static void ttbr_resolve_kallsyms(void)
{
	struct kprobe probe = { .symbol_name = "kallsyms_lookup_name" };

	if (!register_kprobe(&probe)) {
		ttbr_kallsyms_lookup_name =
			(ttbr_kallsyms_lookup_name_t)probe.addr;
		unregister_kprobe(&probe);
	}
}

static struct lk1337_ttbr_split *ttbr_find(struct lk1337_session *session,
						  int id)
{
	struct lk1337_ttbr_split *split;

	list_for_each_entry(split, &session->ttbr_views, session_node)
		if (split->id == id)
			return split;
	return NULL;
}

static bool ttbr_valid_range(unsigned long start, unsigned long end,
				     unsigned int *nr_pages)
{
	u64 size;

	if (!start || (start & ~PAGE_MASK) || (end & ~PAGE_MASK) || end <= start ||
	    start >= TASK_SIZE_64 || end > TASK_SIZE_64)
		return false;
	size = end - start;
	/* The alternate view has one private PMD/PTE chain.  Do not accept a
	 * range that crosses the 2 MiB PMD containing @start; the old 64 MiB
	 * limit silently wrapped pte_index() and installed the wrong pages. */
	if (size > PMD_SIZE || (start & PMD_MASK) != ((end - 1) & PMD_MASK) ||
	    (size >> PAGE_SHIFT) > UINT_MAX)
		return false;
	*nr_pages = size >> PAGE_SHIFT;
	return *nr_pages != 0;
}

static int ttbr_pin_real_page(struct page *page)
{
	if (!page || PageReserved(page) || is_zone_device_page(page))
		return -EINVAL;
	get_page(page);
	return 0;
}

static int ttbr_lookup_source_page(struct mm_struct *mm, unsigned long addr,
						   struct page **result)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pmd_t pmd_entry;
	pte_t *pte;
	pte_t pte_entry;
	spinlock_t *ptl;
	struct page *page = NULL;
	int error = -EFAULT;

	/* Caller holds mmap_read_lock(mm) across the complete source-table walk. */
	pgd = pgd_offset(mm, addr);
	if (pgd_none(READ_ONCE(*pgd)) || pgd_bad(READ_ONCE(*pgd)))
		goto out;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(READ_ONCE(*p4d)) || p4d_bad(READ_ONCE(*p4d)))
		goto out;
	pud = pud_offset(p4d, addr);
	if (pud_none(READ_ONCE(*pud)) || pud_bad(READ_ONCE(*pud)) ||
	    pud_sect(READ_ONCE(*pud)))
		goto out;
	pmd = pmd_offset(pud, addr);
	ptl = pmd_lock(mm, pmd);
	pmd_entry = READ_ONCE(*pmd);
	if (pmd_trans_huge(pmd_entry)) {
		/* A PMD mapping cannot be safely replaced page-by-page without
		 * splitting it through the VM core; require normal PTEs here. */
		error = -EOPNOTSUPP;
		goto pmd_out;
	}
	if (pmd_none(pmd_entry) || pmd_bad(pmd_entry) || !pmd_present(pmd_entry))
		goto pmd_out;
	spin_unlock(ptl);
	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte_entry = READ_ONCE(*pte);
	if (pte_present(pte_entry) && !pte_special(pte_entry) &&
	    pfn_valid(pte_pfn(pte_entry)))
		page = pfn_to_page(pte_pfn(pte_entry));
	pte_unmap_unlock(pte, ptl);
	goto page_out;
pmd_out:
	spin_unlock(ptl);
page_out:
	if (page && !ttbr_pin_real_page(page))
		*result = page;
	else
		page = NULL;
out:
	return page ? 0 : error;
}

static void ttbr_free_pages(struct page **pages, unsigned int count)
{
	unsigned int i;

	if (!pages)
		return;
	for (i = 0; i < count; ++i)
		if (pages[i])
			put_page(pages[i]);
	kvfree(pages);
}

static int ttbr_alloc_alter_pages(struct page **pages, unsigned int count,
					  void __user *buffer)
{
	unsigned int i;
	char *mapped;

	for (i = 0; i < count; ++i) {
		pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pages[i])
			return -ENOMEM;
		mapped = kmap(pages[i]);
		if (copy_from_user(mapped, (char __user *)buffer +
					   ((size_t)i << PAGE_SHIFT), PAGE_SIZE)) {
			kunmap(pages[i]);
			return -EFAULT;
		}
		kunmap(pages[i]);
		flush_dcache_page(pages[i]);
	}
	return 0;
}

/*
 * Build the alter view: a private pgd that SHARES every page-table page of the
 * source mm except for a private pmd+pte chain covering the target range.
 *
 * Sharing is what makes the whole thing work. A fault taken while running the
 * alter view is still handled against current->mm, which stays the source mm,
 * so the fix-up is written into the source's page tables; if the alter view
 * had private copies of them (the dup_mm()/dup_mmap() snapshot the first
 * implementation used) the hardware would keep faulting on the stale copy
 * forever -- e.g. the first write to a COW thread stack. Sharing also means
 * memory mapped after setup is automatically visible in both views.
 *
 * Only PTE-mapped target ranges are supported: a block (2 MB) PMD would have to
 * be split to override a single page.
 */
static int ttbr_build_alter_tables(struct lk1337_ttbr_split *split)
{
	struct mm_struct *src = split->source_mm;
	unsigned long start = split->start;
	pgd_t *spgd = pgd_offset(src, start);
	pud_t *spud;
	pmd_t *spmd;
	pmd_t *spmd_base;
	pte_t *spte_base;
	unsigned int i;

	if (pgd_none(*spgd) || pgd_bad(*spgd))
		return -EFAULT;
	spud = pud_offset(p4d_offset(spgd, start), start);
	if (pud_none(*spud) || pud_bad(*spud) || pud_sect(*spud))
		return -EOPNOTSUPP;
	spmd = pmd_offset(spud, start);
	if (pmd_none(*spmd) || pmd_bad(*spmd) || pmd_sect(*spmd) ||
	    pmd_trans_huge(*spmd))
		return -EOPNOTSUPP;

	split->alter_pgd = (pgd_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	split->alter_pmd = (pmd_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	split->alter_pte = (pte_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!split->alter_pgd || !split->alter_pmd || !split->alter_pte)
		return -ENOMEM;
	if (!pgtable_pmd_page_ctor(virt_to_page(split->alter_pmd)) ||
	    !pgtable_pte_page_ctor(virt_to_page(split->alter_pte)))
		return -ENOMEM;

	memcpy(split->alter_pgd, src->pgd, PAGE_SIZE);
	spmd_base = (pmd_t *)__va(pgd_val(*spgd) & PAGE_MASK);
	spte_base = (pte_t *)__va(pmd_val(*spmd) & PAGE_MASK);
	memcpy(split->alter_pmd, spmd_base, PAGE_SIZE);
	memcpy(split->alter_pte, spte_base, PAGE_SIZE);

	split->target_pgd_index = pgd_index(start);
	split->target_pmd_index = pmd_index(start);
	split->alter_pmd[split->target_pmd_index] =
		__pmd(__pa(split->alter_pte) | PMD_TYPE_TABLE);
	split->alter_pgd[split->target_pgd_index] =
		__pgd(__pa(split->alter_pmd) | PUD_TYPE_TABLE);

	for (i = 0; i < split->nr_pages; ++i) {
		unsigned long addr = start + ((unsigned long)i << PAGE_SHIFT);

		split->alter_pte[pte_index(addr)] =
			pfn_pte(page_to_pfn(split->alter_pages[i]), PAGE_READONLY);
	}
	dsb(ishst);
	pr_info("ttbr: alter pgd=%px (share pgd[%u], private pmd[%u])\n",
		split->alter_pgd, split->target_pgd_index,
		split->target_pmd_index);
	return 0;
}

static void ttbr_free_alter_tables(struct lk1337_ttbr_split *split)
{
	if (split->alter_pte) {
		pgtable_pte_page_dtor(virt_to_page(split->alter_pte));
		free_page((unsigned long)split->alter_pte);
		split->alter_pte = NULL;
	}
	if (split->alter_pmd) {
		pgtable_pmd_page_dtor(virt_to_page(split->alter_pmd));
		free_page((unsigned long)split->alter_pmd);
		split->alter_pmd = NULL;
	}
	if (split->alter_pgd) {
		free_page((unsigned long)split->alter_pgd);
		split->alter_pgd = NULL;
	}
}

/* Repoint the target range at @pages (used by LK1337_TTBR_UPDATE). */
static void ttbr_set_alter_ptes(struct lk1337_ttbr_split *split,
				struct page **pages)
{
	unsigned int i;

	for (i = 0; i < split->nr_pages; ++i) {
		unsigned long addr = split->start + ((unsigned long)i << PAGE_SHIFT);

		set_pte(&split->alter_pte[pte_index(addr)],
			pfn_pte(page_to_pfn(pages[i]), PAGE_READONLY));
	}
	dsb(ishst);
}

/*
 * Invalidate the source mm's ASID on this CPU only.
 *
 * The two views are distinguished purely by the page table in TTBR0 while the
 * ASID stays the source mm's, so an entry cached while running one view is
 * indistinguishable from an entry of the other and must not be reused.
 */
static void ttbr_flush_local_asid(struct mm_struct *mm)
{
	unsigned long asid = __TLBI_VADDR(0, ASID(mm));

	dsb(ishst);
	__tlbi(aside1, asid);
	__tlbi_user(aside1, asid);
	dsb(ish);
}

static void ttbr_flush_asid_cb(void *info)
{
	ttbr_flush_local_asid(info);
}

/* Every CPU may have cached the ASID, so re-syncing after the alter PTEs
 * change has to run everywhere. */
static void ttbr_sync_mm(struct lk1337_ttbr_split *split)
{
	on_each_cpu(ttbr_flush_asid_cb, split->source_mm, 1);
}

/*
 * Record @view_mm's page table as the current task's TTBR0, or the mm's own one
 * when @view_mm is NULL (the executor). The ASID is always taken from
 * @source_mm: it is the source mm that the kernel tracks, and TTBR1_EL1 (which
 * TCR.A1 makes authoritative) still carries it.
 */
/*
 * Point the current CPU at @view_mm's page table.
 *
 * TTBR0_EL1 is programmed here rather than through check_and_switch_context():
 * the ASID is left exactly as the kernel chose for @source_mm (TTBR1_EL1 keeps
 * it, and TCR.A1 makes that copy authoritative), only the translation base
 * changes, so no ASID allocation or locking is involved and this is safe to do
 * from finish_task_switch() with the runqueue lock held.
 *
 * The hardware register is written unconditionally. That is required on CPUs
 * with hardware PAN, where the kernel programs TTBR0 in cpu_do_switch_mm() and
 * never reloads it on the way out -- the KPTI exit trampoline only rewrites
 * TTBR1. The cached copy in thread_info is updated too, because with software
 * PAN __uaccess_ttbr0_enable() reloads TTBR0 from there.
 */
static void ttbr_write_ttbr0(struct mm_struct *source_mm, pgd_t *view_pgd)
{
	unsigned long asid = ASID(source_mm);
	unsigned long ttbr0 = phys_to_ttbr(__pa(view_pgd));

	if (system_supports_cnp() && asid)
		ttbr0 |= TTBR_CNP_BIT;
#ifdef CONFIG_ARM64_SW_TTBR0_PAN
	ttbr0 |= ((u64)asid << 48);
	WRITE_ONCE(task_thread_info(current)->ttbr0, ttbr0);
#endif
	write_sysreg(ttbr0, ttbr0_el1);
	isb();
}

static void ttbr_install_view(struct mm_struct *source_mm, pgd_t *view_pgd)
{
	phys_addr_t pgd_phys;
	unsigned long installed = this_cpu_read(ttbr_active_pgd);

	if (!view_pgd) {
		/* This CPU is not running the split's mm: forget the marker and
		 * drop stale entries if an alter view was live here before. */
		if (installed) {
			ttbr_flush_local_asid(source_mm);
			this_cpu_write(ttbr_active_pgd, 0);
		}
		return;
	}

	pgd_phys = __pa(view_pgd);
	if (installed != (unsigned long)pgd_phys) {
		ttbr_flush_local_asid(source_mm);
		this_cpu_write(ttbr_active_pgd, (unsigned long)pgd_phys);
	}
	ttbr_write_ttbr0(source_mm, view_pgd);
}

/* Run on every CPU while a split goes away: forget the marker, drop the
 * stale ASID entries and put any task that was using the alter view back on
 * its own page table. No check_and_switch_context() here: it allocates ASIDs
 * and takes locks, which is exactly what made the old implementation unsafe. */
static void ttbr_force_source(void *data)
{
	struct lk1337_ttbr_split *split = data;

	this_cpu_write(ttbr_active_pgd, 0);
	ttbr_flush_local_asid(split->source_mm);
	if (current->mm != split->source_mm)
		return;
	/*
	 * Restore what this task is supposed to see once the split is gone.  In
	 * the default mode that is the source view for everyone; in
	 * executor-alter mode the executor is the exception, because after the
	 * split is gone nothing else would put it back on the alter view.
	 */
	if (split->executor_alter &&
	    task_pid_vnr(current) == split->executor_tid)
		ttbr_write_ttbr0(split->source_mm, split->alter_pgd);
	else
		ttbr_write_ttbr0(split->source_mm, split->source_mm->pgd);
}

static void ttbr_probes_disarm(void);
static void ttbr_probes_arm(void);

static void ttbr_release_split(struct lk1337_ttbr_split *split)
{
	on_each_cpu(ttbr_force_source, split, 1);
	wait_event(split->switch_wait, refcount_read(&split->switch_refs) == 1);
	ttbr_sync_mm(split);
	ttbr_free_alter_tables(split);
	ttbr_free_pages(split->alter_pages, split->nr_pages);
	ttbr_free_pages(split->real_pages, split->nr_pages);
	mmdrop(split->source_mm);
	kvfree(split->alter_phys);
	kvfree(split->real_phys);
	kfree(split);
}

static void ttbr_destroy_split(struct lk1337_session *session,
				       struct lk1337_ttbr_split *split)
{
	unsigned long flags;
	mutex_lock(&ttbr_global_lock);
	raw_spin_lock_irqsave(&ttbr_split_lock, flags);
	if (split->active) {
		split->active = false;
		list_del_init(&split->global_node);
	}
	raw_spin_unlock_irqrestore(&ttbr_split_lock, flags);
	/*
	 * Withdraw the split from the lock-free fast path and wait for every
	 * in-flight reader to finish before anything is freed.  A reader that
	 * already loaded the pointer may still dereference it; synchronize_rcu()
	 * gives it until the next grace period.
	 */
	if (rcu_access_pointer(ttbr_active_split) == split)
		rcu_assign_pointer(ttbr_active_split, NULL);
	mutex_unlock(&ttbr_global_lock);
	synchronize_rcu();
	list_del_init(&split->session_node);
	/*
	 * Drop the hooks before the split is freed.  The refcount guarantees the
	 * last destroy (from LK1337_TTBR_DESTROY, a session close or module
	 * unload) removes them, so an idle module leaves the scheduler alone.
	 */
	ttbr_probes_disarm();
	ttbr_release_split(split);
}

/*
 * finish_task_switch() is static and called exactly once, so ThinLTO may
 * inline its only call site: the symbol still exists in kallsyms and accepts a
 * kprobe, but the standalone body is never executed and the probe never fires.
 * __schedule() is the common out-of-line path for every switch (voluntary,
 * preemptive and idle), so the view is installed from its post-handler, which
 * runs with current == the scheduled-in task.
 */
static void ttbr_schedule_post(struct kprobe *probe, struct pt_regs *regs,
			       unsigned long flags)
{
	struct lk1337_ttbr_split *split;
	struct mm_struct *mm = current->mm;
	pgd_t *view = NULL;

	if (!mm)
		return;

	/*
	 * Lock-free: no spinlock, no list walk.  The published pointer is only
	 * written from process context and readers are protected by RCU, so this
	 * is a couple of loads in the common case (no split, or the split's
	 * executor).  This runs on every context switch in the system, so it has
	 * to stay this cheap.
	 */
	rcu_read_lock();
	split = rcu_dereference(ttbr_active_split);
	if (split && split->active && split->source_mm == mm) {
		bool is_executor = task_pid_vnr(current) == split->executor_tid;

		/*
		 * Default: the executor keeps the original view, every other
		 * thread sees the alter view.  With LK1337_TTBR_F_EXECUTOR_ALTER
		 * the mapping is inverted: the executor is the thread that sees
		 * the alter view.
		 */
		if (is_executor == split->executor_alter)
			view = split->alter_pgd;
		else
			view = mm->pgd;
	}
	rcu_read_unlock();

	ttbr_install_view(mm, view);
}

static struct lk1337_probe ttbr_schedule_probe =
	LK1337_PROBE("__schedule", "ttbr", NULL, ttbr_schedule_post);

static int ttbr_do_exit(struct kprobe *probe, struct pt_regs *regs)
{
	struct lk1337_ttbr_split *split;
	unsigned long flags;

	/*
	 * Only the executor is supposed to see the source view; with it gone
	 * every thread of the process would start seeing the alter view, which
	 * is a snapshot of the address space and would soon crash the program.
	 * Retire the split instead and leave the process on its own page table.
	 */
	raw_spin_lock_irqsave(&ttbr_split_lock, flags);
	list_for_each_entry(split, &ttbr_splits, global_node) {
		if (split->active && split->source_mm == current->mm &&
		    split->executor_tid == task_pid_vnr(current)) {
			split->active = false;
			list_del_init(&split->global_node);
		}
	}
	raw_spin_unlock_irqrestore(&ttbr_split_lock, flags);
	return 0;
}

static int ttbr_begin_exec(struct kprobe *probe, struct pt_regs *regs)
{
	struct lk1337_ttbr_split *split;
	unsigned long flags;

	raw_spin_lock_irqsave(&ttbr_split_lock, flags);
	list_for_each_entry(split, &ttbr_splits, global_node)
		if (split->source_mm == current->mm)
			split->executor_tid = 0;
	raw_spin_unlock_irqrestore(&ttbr_split_lock, flags);
	return 0;
}

/*
 * The three TTBR hooks are refcounted together: the view is only selected by
 * the __schedule post-handler while at least one split exists, so with no split
 * configured the module does not touch the scheduler at all.
 */
static struct lk1337_probe ttbr_exit_probe =
	LK1337_PROBE("do_exit", "ttbr", ttbr_do_exit, NULL);
static struct lk1337_probe ttbr_exec_probe =
	LK1337_PROBE("begin_new_exec", "ttbr", ttbr_begin_exec, NULL);
static unsigned int ttbr_probe_refs;
static DEFINE_MUTEX(ttbr_probe_lock);

static void ttbr_probes_arm(void)
{
	mutex_lock(&ttbr_probe_lock);
	if (ttbr_probe_refs++ == 0) {
		if (lk1337_probe_use(&ttbr_schedule_probe))
			pr_warn("ttbr: __schedule hook unavailable, views will not switch\n");
		if (lk1337_probe_use(&ttbr_exit_probe))
			pr_warn("ttbr: do_exit hook unavailable, splits may outlive their executor\n");
		if (lk1337_probe_use(&ttbr_exec_probe))
			pr_warn("ttbr: begin_new_exec hook unavailable\n");
	}
	mutex_unlock(&ttbr_probe_lock);
}

static void ttbr_probes_disarm(void)
{
	mutex_lock(&ttbr_probe_lock);
	if (ttbr_probe_refs && --ttbr_probe_refs == 0) {
		lk1337_probe_release(&ttbr_exec_probe);
		lk1337_probe_release(&ttbr_exit_probe);
		lk1337_probe_release(&ttbr_schedule_probe);
	}
	mutex_unlock(&ttbr_probe_lock);
}

static int ttbr_set_executor(struct lk1337_ttbr_split *split, pid_t tid)
{
	struct pid *pid;
	struct task_struct *task;
	struct mm_struct *mm;

	if (tid <= 0)
		return -EINVAL;
	pid = find_get_pid(tid);
	if (!pid)
		return -ESRCH;
	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!task)
		return -ESRCH;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -EINVAL;
	if (mm != split->source_mm) {
		mmput(mm);
		return -EXDEV;
	}
	mmput(mm);
	mutex_lock(&split->lock);
	split->executor_tid = tid;
	mutex_unlock(&split->lock);
	return 0;
}

int lk1337_ttbr_init(void)
{
	int ret;

	ttbr_resolve_kallsyms();
	/* check_and_switch_context() is deliberately NOT used: the view switch
	 * is a thread_info->ttbr0 store, which avoids its ASID allocation and
	 * locking entirely. */
	ret = ttbr_resolve(&ttbr_get_locked_pte, "__get_locked_pte");
	if (ret) {
		pr_err("resolve __get_locked_pte failed: %d\n", ret);
		return ret;
	}
	/*
	 * No probe is registered here.  The __schedule/do_exit/begin_new_exec
	 * hooks are installed by the first LK1337_TTBR_SETUP and removed again
	 * when the last view is destroyed, so an idle module costs nothing on
	 * the scheduler.
	 */
	pr_info("per-thread TTBR views ready (hooks installed on demand)\n");
	return 0;
}

void lk1337_ttbr_exit(void)
{
	mutex_lock(&ttbr_probe_lock);
	if (ttbr_probe_refs) {
		ttbr_probe_refs = 0;
		lk1337_probe_release(&ttbr_exec_probe);
		lk1337_probe_release(&ttbr_exit_probe);
		lk1337_probe_release(&ttbr_schedule_probe);
	}
	mutex_unlock(&ttbr_probe_lock);
}

void lk1337_ttbr_session_release(struct lk1337_session *session)
{
	struct lk1337_ttbr_split *split, *next;

	list_for_each_entry_safe(split, next, &session->ttbr_views, session_node)
		ttbr_destroy_split(session, split);
}

long lk1337_ttbr_dispatch(struct lk1337_session *session, unsigned int cmd,
				  void __user *arg)
{
	struct lk1337_ttbr_setup setup;
	struct lk1337_ttbr_update update;
	struct lk1337_ttbr_executor executor;
	struct lk1337_ttbr_query query;
	struct lk1337_ttbr_split *split = NULL, *other = NULL;
	struct task_struct *source_task;
	struct pid *source_pid;
	struct mm_struct *source_mm;
	struct page **real_pages = NULL, **alter_pages = NULL;
	phys_addr_t *real_phys = NULL, *alter_phys = NULL;
	unsigned int nr_pages = 0, i;
	int ret;

	switch (cmd) {
	case LK1337_TTBR_SETUP:
		if (copy_from_user(&setup, arg, sizeof(setup)))
			return -EFAULT;
		if ((setup.flags & LK1337_TTBR_F_EXECUTOR_ALTER) ||
		    (setup.flags & ~LK1337_TTBR_F_EXECUTOR_SOURCE) ||
		    setup.executor_tid <= 0 ||
		    !ttbr_valid_range(setup.start, setup.end, &nr_pages) ||
		    !setup.alter_mem || setup.source_pid < 0)
			return -EINVAL;
		source_pid = find_get_pid(setup.source_pid ? setup.source_pid :
						  setup.executor_tid);
		if (!source_pid)
			return -ESRCH;
		source_task = get_pid_task(source_pid, PIDTYPE_PID);
		put_pid(source_pid);
		if (!source_task)
			return -ESRCH;
		source_mm = get_task_mm(source_task);
		if (!source_mm) {
			put_task_struct(source_task);
			return -EINVAL;
		}
		/* The executor selects the view by tid, so it has to be a thread
		 * of the same address space. */
		{
			struct pid *epid = find_get_pid(setup.executor_tid);
			struct task_struct *etask = epid ?
				get_pid_task(epid, PIDTYPE_PID) : NULL;

			put_pid(epid);
			if (!etask || etask->mm != source_mm) {
				put_task_struct(etask);
				mmput(source_mm);
				put_task_struct(source_task);
				return etask ? -EXDEV : -ESRCH;
			}
			put_task_struct(etask);
		}
		mutex_lock(&ttbr_global_lock);
		list_for_each_entry(other, &ttbr_splits, global_node)
			if (other->source_mm == source_mm) {
				mutex_unlock(&ttbr_global_lock);
				mmput(source_mm);
				put_task_struct(source_task);
				return -EBUSY;
			}
		mutex_unlock(&ttbr_global_lock);
		real_pages = kcalloc(nr_pages, sizeof(*real_pages), GFP_KERNEL);
		alter_pages = kcalloc(nr_pages, sizeof(*alter_pages), GFP_KERNEL);
		real_phys = kvcalloc(nr_pages, sizeof(*real_phys), GFP_KERNEL);
		alter_phys = kvcalloc(nr_pages, sizeof(*alter_phys), GFP_KERNEL);
		if (!real_pages || !alter_pages || !real_phys || !alter_phys) {
			ret = -ENOMEM;
			goto setup_fail;
		}
		ret = ttbr_alloc_alter_pages(alter_pages, nr_pages,
					     u64_to_user_ptr(setup.alter_mem));
		if (ret)
			goto setup_fail;
		split = kzalloc(sizeof(*split), GFP_KERNEL);
		if (!split) {
			ret = -ENOMEM;
			goto setup_fail;
		}
		mutex_init(&split->lock);
		init_waitqueue_head(&split->switch_wait);
		refcount_set(&split->switch_refs, 1);
		split->source_mm = source_mm;
		split->source_pid = task_tgid_vnr(source_task);
		split->executor_tid = setup.executor_tid;
		split->start = setup.start;
		split->end = setup.end;
		/* Default is executor-alter; the flag asks for the old direction. */
		split->executor_alter =
			!(setup.flags & LK1337_TTBR_F_EXECUTOR_SOURCE);
		split->nr_pages = nr_pages;
		split->real_pages = real_pages;
		split->alter_pages = alter_pages;
		split->real_phys = real_phys;
		split->alter_phys = alter_phys;
		split->id = atomic_inc_return(&ttbr_next_id);
		split->active = true;
		INIT_LIST_HEAD(&split->session_node);
		INIT_LIST_HEAD(&split->global_node);
		for (i = 0; i < nr_pages; ++i)
			alter_phys[i] = page_to_phys(alter_pages[i]);
		/* Keep the source address space stable while both the real-page walk
		 * and the private table clone inspect its page tables.  The user copy
		 * above is deliberately completed before taking this lock so a fault in
		 * the caller's alter buffer cannot recurse through mmap_lock. */
		mmap_read_lock(source_mm);
		for (i = 0; i < nr_pages; ++i) {
			ret = ttbr_lookup_source_page(source_mm,
						      setup.start + ((unsigned long)i << PAGE_SHIFT),
						      &real_pages[i]);
			if (ret)
				break;
			real_phys[i] = page_to_phys(real_pages[i]);
		}
		if (!ret)
			ret = ttbr_build_alter_tables(split);
		mmap_read_unlock(source_mm);
		if (ret)
			goto setup_fail;
		mutex_lock(&ttbr_global_lock);
		list_for_each_entry(other, &ttbr_splits, global_node)
			if (other->source_mm == source_mm) {
				mutex_unlock(&ttbr_global_lock);
				ret = -EBUSY;
				goto setup_fail;
			}
		list_add_tail(&split->global_node, &ttbr_splits);
		list_add_tail(&split->session_node, &session->ttbr_views);
		/* Publish for the lock-free per-switch path. */
		rcu_assign_pointer(ttbr_active_split, split);
		mutex_unlock(&ttbr_global_lock);
		/* First live split: install the scheduler/exit hooks. */
		ttbr_probes_arm();
		/* Keep the mm_struct alive without keeping mm_users, so the
		 * process can still exit and run exit_mmap() normally. */
		mmgrab(source_mm);
		mmput(source_mm);
		put_task_struct(source_task);
		setup.view_id = split->id;
		if (copy_to_user(arg, &setup, sizeof(setup))) {
			ttbr_destroy_split(session, split);
			return -EFAULT;
		}
		return 0;
	setup_fail:
		if (split) {
			ttbr_free_alter_tables(split);
			kfree(split);
		}
		ttbr_free_pages(alter_pages, nr_pages);
		ttbr_free_pages(real_pages, nr_pages);
		kvfree(alter_phys);
		kvfree(real_phys);
		mmput(source_mm);
		put_task_struct(source_task);
		return ret;
	case LK1337_TTBR_UPDATE:
		if (copy_from_user(&update, arg, sizeof(update)))
			return -EFAULT;
		split = ttbr_find(session, update.view_id);
		if (!split || update.start != split->start || update.end != split->end ||
		    update.flags || !update.alter_mem)
			return split ? -EINVAL : -ENOENT;
		alter_pages = kcalloc(split->nr_pages, sizeof(*alter_pages), GFP_KERNEL);
		if (!alter_pages)
			return -ENOMEM;
		ret = ttbr_alloc_alter_pages(alter_pages, split->nr_pages,
						     u64_to_user_ptr(update.alter_mem));
		if (ret) {
			ttbr_free_pages(alter_pages, split->nr_pages);
			return ret;
		}
		mutex_lock(&split->lock);
		ttbr_set_alter_ptes(split, alter_pages);
		ttbr_sync_mm(split);
		{
			struct page **old = split->alter_pages;

			split->alter_pages = alter_pages;
			for (i = 0; i < split->nr_pages; ++i)
				split->alter_phys[i] = page_to_phys(alter_pages[i]);
			ttbr_free_pages(old, split->nr_pages);
			alter_pages = NULL;
		}
		mutex_unlock(&split->lock);
		return ret;
	case LK1337_TTBR_SET_EXECUTOR:
		if (copy_from_user(&executor, arg, sizeof(executor)))
			return -EFAULT;
		split = ttbr_find(session, executor.view_id);
		return split ? ttbr_set_executor(split, executor.executor_tid) : -ENOENT;
	case LK1337_TTBR_CLEAR_EXECUTOR:
		if (copy_from_user(&executor, arg, sizeof(executor)))
			return -EFAULT;
		split = ttbr_find(session, executor.view_id);
		if (!split)
			return -ENOENT;
		mutex_lock(&split->lock);
		split->executor_tid = 0;
		mutex_unlock(&split->lock);
		return 0;
	case LK1337_TTBR_DESTROY:
		if (copy_from_user(&executor, arg, sizeof(executor)))
			return -EFAULT;
		split = ttbr_find(session, executor.view_id);
		if (!split)
			return -ENOENT;
		ttbr_destroy_split(session, split);
		return 0;
	case LK1337_TTBR_QUERY:
		if (copy_from_user(&query, arg, sizeof(query)))
			return -EFAULT;
		split = ttbr_find(session, query.view_id);
		if (!split)
			return -ENOENT;
		mutex_lock(&split->lock);
		query.source_pid = split->source_pid;
		query.executor_tid = split->executor_tid;
		query.flags = split->executor_alter ? 0 : LK1337_TTBR_F_EXECUTOR_SOURCE;
		query.start = split->start;
		query.end = split->end;
		query.size = split->end - split->start;
		query.nr_pages = split->nr_pages;
		query.source_pgd_phys = __pa(split->source_mm->pgd);
		query.alter_pgd_phys = __pa(split->alter_pgd);
		query.source_asid = atomic64_read(&split->source_mm->context.id);
		/* both views are walked with the source mm's ASID by design */
		query.alter_asid = ASID(split->source_mm);
		query.page_count = split->nr_pages;
		if (query.page_capacity && query.page_capacity < split->nr_pages) {
			mutex_unlock(&split->lock);
			return -ENOSPC;
		}
		if (query.page_capacity &&
		    (copy_to_user(u64_to_user_ptr(query.real_phys_array), split->real_phys,
				  split->nr_pages * sizeof(*split->real_phys)) ||
		     copy_to_user(u64_to_user_ptr(query.alter_phys_array), split->alter_phys,
				  split->nr_pages * sizeof(*split->alter_phys)))) {
			mutex_unlock(&split->lock);
			return -EFAULT;
		}
		mutex_unlock(&split->lock);
		return copy_to_user(arg, &query, sizeof(query)) ? -EFAULT : 0;
	default:
		return -ENOTTY;
	}
}
