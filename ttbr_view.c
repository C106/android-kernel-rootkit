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
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "debugger_uapi.h"
#include "ttbr_view.h"

struct lk1337_session {
	struct mutex lock;
	struct list_head breakpoints;
	struct list_head ttbr_views;
	void *memory_bounce;
	int next_id;
};

typedef struct mm_struct *(*ttbr_dup_mm_t)(struct task_struct *,
							struct mm_struct *);
typedef struct mm_struct *(*ttbr_mm_alloc_t)(void);
typedef int (*ttbr_dup_mmap_t)(struct mm_struct *, struct mm_struct *);
typedef unsigned long (*ttbr_kallsyms_lookup_name_t)(const char *);
typedef void (*ttbr_check_context_t)(struct mm_struct *);
typedef pte_t *(*ttbr_get_locked_pte_t)(struct mm_struct *, unsigned long,
							spinlock_t **);

static ttbr_dup_mm_t ttbr_dup_mm;
static ttbr_mm_alloc_t ttbr_mm_alloc;
static ttbr_dup_mmap_t ttbr_dup_mmap;
static ttbr_kallsyms_lookup_name_t ttbr_kallsyms_lookup_name;
static ttbr_check_context_t ttbr_check_context;
static ttbr_get_locked_pte_t ttbr_get_locked_pte;
static DEFINE_MUTEX(ttbr_global_lock);
static DEFINE_RAW_SPINLOCK(ttbr_split_lock);
static LIST_HEAD(ttbr_splits);
static atomic_t ttbr_next_id = ATOMIC_INIT(1);
static struct kprobe ttbr_exit_kp;
static struct kprobe ttbr_exec_kp;
static struct kprobe ttbr_switch_kp;
static bool ttbr_exit_registered;
static bool ttbr_exec_registered;
static bool ttbr_switch_registered;

struct lk1337_ttbr_split {
	struct list_head session_node;
	struct list_head global_node;
	struct mm_struct *source_mm;
	struct mm_struct *alter_mm;
	struct page **real_pages;
	struct page **alter_pages;
	phys_addr_t *real_phys;
	phys_addr_t *alter_phys;
	unsigned long start;
	unsigned long end;
	unsigned int nr_pages;
	pid_t source_pid;
	pid_t executor_tid;
	struct mutex lock;
	refcount_t switch_refs;
	wait_queue_head_t switch_wait;
	bool active;
	int id;
};

static DEFINE_PER_CPU(struct lk1337_ttbr_split *, ttbr_active_split);

static __nocfi struct mm_struct *ttbr_call_dup_mm(struct task_struct *task,
							  struct mm_struct *source)
{
	return ttbr_dup_mm(task, source);
}

static __nocfi struct mm_struct *ttbr_call_mm_alloc(void)
{
	return ttbr_mm_alloc();
}

static __nocfi int ttbr_call_dup_mmap(struct mm_struct *mm,
						struct mm_struct *source)
{
	return ttbr_dup_mmap(mm, source);
}

static __nocfi void ttbr_call_check_context(struct mm_struct *mm)
{
	ttbr_check_context(mm);
}

static __nocfi pte_t *ttbr_call_get_locked_pte(struct mm_struct *mm,
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

static struct mm_struct *ttbr_clone_mm(struct task_struct *task,
					       struct mm_struct *source)
{
	struct mm_struct *mm;
	int ret;

	if (ttbr_dup_mm)
		return ttbr_call_dup_mm(task, source);
	if (!ttbr_mm_alloc || !ttbr_dup_mmap)
		return NULL;
	mm = ttbr_call_mm_alloc();
	if (!mm)
		return NULL;
	ret = ttbr_call_dup_mmap(mm, source);
	if (ret) {
		mmput(mm);
		return NULL;
	}
	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;
	return mm;
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
	if (size > SZ_64M || (size >> PAGE_SHIFT) > UINT_MAX)
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

	mmap_read_lock(mm);
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
	mmap_read_unlock(mm);
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

static int ttbr_prepare_ptes(struct mm_struct *mm, unsigned long start,
				     unsigned int count)
{
	unsigned int i;
	spinlock_t *ptl;
	pte_t *ptep;

	mmap_write_lock(mm);
	for (i = 0; i < count; ++i) {
		ptep = ttbr_call_get_locked_pte(mm, start + ((unsigned long)i << PAGE_SHIFT),
					   &ptl);
		if (!ptep) {
			mmap_write_unlock(mm);
			return -ENOMEM;
		}
		pte_unmap_unlock(ptep, ptl);
	}
	mmap_write_unlock(mm);
	return 0;
}

static void ttbr_set_alter_ptes(struct lk1337_ttbr_split *split,
					struct page **pages)
{
	unsigned int i;
	spinlock_t *ptl;
	pte_t *ptep;

	mmap_write_lock(split->alter_mm);
	for (i = 0; i < split->nr_pages; ++i) {
		ptep = ttbr_call_get_locked_pte(split->alter_mm,
					   split->start + ((unsigned long)i << PAGE_SHIFT), &ptl);
		if (!ptep)
			continue;
		set_pte_at(split->alter_mm,
			   split->start + ((unsigned long)i << PAGE_SHIFT), ptep,
			   pfn_pte(page_to_pfn(pages[i]), PAGE_READONLY));
		pte_unmap_unlock(ptep, ptl);
	}
	mmap_write_unlock(split->alter_mm);
}

static void ttbr_clear_alter_ptes(struct lk1337_ttbr_split *split)
{
	unsigned int i;
	spinlock_t *ptl;
	pte_t *ptep;
	pte_t entry;

	mmap_write_lock(split->alter_mm);
	for (i = 0; i < split->nr_pages; ++i) {
		ptep = ttbr_call_get_locked_pte(split->alter_mm,
					   split->start + ((unsigned long)i << PAGE_SHIFT), &ptl);
		if (!ptep)
			continue;
		entry = READ_ONCE(*ptep);
		if (pte_present(entry) && pte_pfn(entry) == page_to_pfn(split->alter_pages[i]))
			pte_clear(split->alter_mm,
				  split->start + ((unsigned long)i << PAGE_SHIFT), ptep);
		pte_unmap_unlock(ptep, ptl);
	}
	mmap_write_unlock(split->alter_mm);
}

static void ttbr_sync_mm(struct mm_struct *mm)
{
	flush_tlb_mm(mm);
	dsb(ish);
	isb();
}

static void ttbr_force_source(void *data)
{
	struct lk1337_ttbr_split *split = data;

	if (this_cpu_read(ttbr_active_split) != split)
		return;
	ttbr_call_check_context(split->source_mm);
	if (current->mm)
		ttbr_update_saved_ttbr0(current, split->source_mm);
	this_cpu_write(ttbr_active_split, NULL);
}

static void ttbr_release_split(struct lk1337_ttbr_split *split)
{
	on_each_cpu(ttbr_force_source, split, 1);
	wait_event(split->switch_wait, refcount_read(&split->switch_refs) == 1);
	ttbr_clear_alter_ptes(split);
	ttbr_sync_mm(split->alter_mm);
	ttbr_free_pages(split->alter_pages, split->nr_pages);
	ttbr_free_pages(split->real_pages, split->nr_pages);
	mmput(split->alter_mm);
	mmput(split->source_mm);
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
	mutex_unlock(&ttbr_global_lock);
	list_del_init(&split->session_node);
	ttbr_release_split(split);
}

static int ttbr_finish_task_switch(struct kprobe *probe, struct pt_regs *regs)
{
	/* This kprobe executes while scheduler rq locks are held. Calling
	 * check_and_switch_context() here is unsafe on GKI and can deadlock the
	 * reader thread. Real TTBR selection must be wired into arch context_switch
	 * or an exported vendor scheduler hook. */
	return 0;
#if 0
	struct lk1337_ttbr_split *split;
	struct lk1337_ttbr_split *found = NULL;
	struct mm_struct *target = current->mm ? current->mm : current->active_mm;
	unsigned long flags;
	bool reader = false;

	raw_spin_lock_irqsave(&ttbr_split_lock, flags);
	list_for_each_entry(split, &ttbr_splits, global_node) {
		if (!split->active || split->source_mm != current->mm)
			continue;
		if (!refcount_inc_not_zero(&split->switch_refs))
			continue;
		found = split;
	if (task_pid_vnr(current) != split->executor_tid) {
		target = split->alter_mm;
		reader = true;
	}
	if (reader && atomic_inc_return(&ttbr_switch_debug) <= 16)
		pr_info("reader switch tid=%d source=%px alter=%px target=%px\n",
			task_pid_vnr(current), split->source_mm, split->alter_mm, target);
		break;
	}
	raw_spin_unlock_irqrestore(&ttbr_split_lock, flags);
	ttbr_call_check_context(target);
	if (current->mm)
		ttbr_update_saved_ttbr0(current, target);
	this_cpu_write(ttbr_active_split,
			(unsigned long)(reader ? found : NULL));
	if (found)
		ttbr_switch_ref_put(found);
	return 0;
#endif
}

static int ttbr_do_exit(struct kprobe *probe, struct pt_regs *regs)
{
	struct lk1337_ttbr_split *split;
	unsigned long flags;

	raw_spin_lock_irqsave(&ttbr_split_lock, flags);
	list_for_each_entry(split, &ttbr_splits, global_node)
		if (split->source_mm == current->mm && split->executor_tid == task_pid_vnr(current))
			split->executor_tid = 0;
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
	ret = ttbr_resolve(&ttbr_dup_mm, "dup_mm");
	if (ret) {
		pr_warn("resolve dup_mm failed: %d (kallsyms=%s); trying mm_alloc/dup_mmap\n",
			ret, ttbr_kallsyms_lookup_name ? "available" : "unavailable");
		ttbr_dup_mm = NULL;
	}
	if (!ttbr_dup_mm) {
		if (ttbr_resolve(&ttbr_mm_alloc, "mm_alloc") ||
		    ttbr_resolve(&ttbr_dup_mmap, "dup_mmap"))
			pr_warn("mm_alloc/dup_mmap fallback unavailable\n");
		else
			pr_info("using mm_alloc/dup_mmap address-space clone fallback\n");
	}
	ret = ttbr_resolve(&ttbr_check_context, "check_and_switch_context");
	if (ret) {
		pr_err("resolve check_and_switch_context failed: %d\n", ret);
		return ret;
	}
	ret = ttbr_resolve(&ttbr_get_locked_pte, "__get_locked_pte");
	if (ret) {
		pr_err("resolve __get_locked_pte failed: %d\n", ret);
		return ret;
	}
	ttbr_exit_kp.symbol_name = "do_exit";
	ttbr_exit_kp.pre_handler = ttbr_do_exit;
	ret = register_kprobe(&ttbr_exit_kp);
	if (ret) {
		pr_warn("register do_exit kprobe failed: %d\n", ret);
	} else {
		ttbr_exit_registered = true;
	}
	ttbr_switch_kp.symbol_name = "finish_task_switch";
	ttbr_switch_kp.pre_handler = ttbr_finish_task_switch;
	ret = register_kprobe(&ttbr_switch_kp);
	if (ret) {
		pr_warn("register finish_task_switch kprobe failed: %d\n", ret);
	} else {
		ttbr_switch_registered = true;
	}
	ttbr_exec_kp.symbol_name = "begin_new_exec";
	ttbr_exec_kp.pre_handler = ttbr_begin_exec;
	ret = register_kprobe(&ttbr_exec_kp);
	if (ret) {
		pr_warn("register begin_new_exec kprobe failed: %d\n", ret);
	} else {
		ttbr_exec_registered = true;
	}
	pr_info("initialized source/alter per-thread TTBR views\n");
	return 0;
}

void lk1337_ttbr_exit(void)
{
	if (ttbr_exec_registered)
		unregister_kprobe(&ttbr_exec_kp);
	if (ttbr_switch_registered)
		unregister_kprobe(&ttbr_switch_kp);
	if (ttbr_exit_registered)
		unregister_kprobe(&ttbr_exit_kp);
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
		return -EOPNOTSUPP;
		if (copy_from_user(&setup, arg, sizeof(setup)))
			return -EFAULT;
		if (setup.flags || setup.executor_tid <= 0 ||
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
		for (i = 0; i < nr_pages; ++i) {
			ret = ttbr_lookup_source_page(source_mm,
						      setup.start + ((unsigned long)i << PAGE_SHIFT),
						      &real_pages[i]);
			if (ret)
				goto setup_fail;
			real_phys[i] = page_to_phys(real_pages[i]);
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
		split->nr_pages = nr_pages;
		split->real_pages = real_pages;
		split->alter_pages = alter_pages;
		split->real_phys = real_phys;
		split->alter_phys = alter_phys;
		split->id = atomic_inc_return(&ttbr_next_id);
		split->active = true;
		INIT_LIST_HEAD(&split->session_node);
		INIT_LIST_HEAD(&split->global_node);
		split->alter_mm = ttbr_clone_mm(source_task, source_mm);
		if (!split->alter_mm) {
			ret = -ENOMEM;
			goto setup_fail;
		}
		ret = ttbr_prepare_ptes(split->alter_mm, split->start, split->nr_pages);
		if (ret) {
			mmput(split->alter_mm);
			split->alter_mm = NULL;
			goto setup_fail;
		}
		for (i = 0; i < nr_pages; ++i)
			alter_phys[i] = page_to_phys(alter_pages[i]);
		ttbr_set_alter_ptes(split, alter_pages);
		ttbr_sync_mm(split->alter_mm);
		mutex_lock(&ttbr_global_lock);
		list_for_each_entry(other, &ttbr_splits, global_node)
			if (other->source_mm == source_mm) {
				mutex_unlock(&ttbr_global_lock);
				ret = -EBUSY;
				goto setup_fail;
			}
		list_add_tail(&split->global_node, &ttbr_splits);
		list_add_tail(&split->session_node, &session->ttbr_views);
		mutex_unlock(&ttbr_global_lock);
		put_task_struct(source_task);
		setup.view_id = split->id;
		if (copy_to_user(arg, &setup, sizeof(setup))) {
			ttbr_destroy_split(session, split);
			return -EFAULT;
		}
		return 0;
	setup_fail:
		if (split) {
			if (split->alter_mm)
				mmput(split->alter_mm);
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
		ret = ttbr_prepare_ptes(split->alter_mm, split->start, split->nr_pages);
		if (!ret) {
			ttbr_set_alter_ptes(split, alter_pages);
			ttbr_sync_mm(split->alter_mm);
			{
				struct page **old = split->alter_pages;
				split->alter_pages = alter_pages;
				for (i = 0; i < split->nr_pages; ++i)
					split->alter_phys[i] = page_to_phys(alter_pages[i]);
				ttbr_free_pages(old, split->nr_pages);
			}
		} else {
			ttbr_free_pages(alter_pages, split->nr_pages);
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
		query.start = split->start;
		query.end = split->end;
		query.size = split->end - split->start;
		query.nr_pages = split->nr_pages;
		query.source_pgd_phys = __pa(split->source_mm->pgd);
		query.alter_pgd_phys = __pa(split->alter_mm->pgd);
		query.source_asid = atomic64_read(&split->source_mm->context.id);
		query.alter_asid = atomic64_read(&split->alter_mm->context.id);
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
