#ifndef LK1337_MEMORY_H
#define LK1337_MEMORY_H

#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

static struct page *lk1337_resolve_page(struct mm_struct *mm, unsigned long addr,
				   bool write, int *error, struct vm_area_struct **cached_vma)
{
	struct vm_area_struct *vma;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pmd_t middle;
	pte_t *pte;
	pte_t entry;
	spinlock_t *lock;
	struct page *page = NULL;
	unsigned long pfn;

	*error = -EFAULT;
	vma = *cached_vma;
	if (!vma || addr < vma->vm_start || addr >= vma->vm_end) {
		vma = find_vma(mm, addr);
		*cached_vma = vma;
	}
	if (!vma || addr < vma->vm_start || vma->vm_flags & (VM_IO | VM_PFNMAP))
		return NULL;
	if (!(vma->vm_flags & (write ? VM_WRITE : VM_READ))) {
		*error = -EACCES;
		return NULL;
	}
	pgd = pgd_offset(mm, addr);
	if (pgd_none(READ_ONCE(*pgd)) || pgd_bad(READ_ONCE(*pgd)))
		return NULL;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(READ_ONCE(*p4d)) || p4d_bad(READ_ONCE(*p4d)))
		return NULL;
	pud = pud_offset(p4d, addr);
	if (pud_none(READ_ONCE(*pud)) || pud_sect(READ_ONCE(*pud)) ||
	    pud_bad(READ_ONCE(*pud)))
		return NULL;
	pmd = pmd_offset(pud, addr);
	lock = pmd_lock(mm, pmd);
	middle = READ_ONCE(*pmd);
	if (pmd_trans_huge(middle)) {
		if (!pmd_present(middle) || (write && !pmd_write(middle)))
			goto unlock;
		pfn = pmd_pfn(middle) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
		if (!pfn_valid(pfn))
			goto unlock;
		page = pfn_to_page(pfn);
		get_page(page);
		spin_unlock(lock);
		return page;
	}
	if (pmd_none(middle) || pmd_bad(middle) || !pmd_present(middle))
		goto unlock;
	spin_unlock(lock);
	pte = pte_offset_map_lock(mm, pmd, addr, &lock);
	entry = READ_ONCE(*pte);
	if (pte_present(entry) && !pte_special(entry) &&
	    (!write || pte_write(entry)) && pfn_valid(pte_pfn(entry))) {
		page = pfn_to_page(pte_pfn(entry));
		get_page(page);
	}
	pte_unmap_unlock(pte, lock);
	return page;
unlock:
	spin_unlock(lock);
	return NULL;
}

static int lk1337_memory_transfer(struct lk1337_memory *request, bool write,
				  void *session_bounce)
{
	struct pid *target;
	struct task_struct *task;
	struct mm_struct *mm;
	struct page *page;
	struct vm_area_struct *cached_vma = NULL;
	char *bounce, *mapped;
	void __user *buffer = u64_to_user_ptr(request->buffer);
	unsigned long addr = request->addr;
	size_t remaining = request->size, chunk, offset;
	int error = 0;

	if (request->pid <= 0 || remaining > SZ_16M ||
	    addr >= TASK_SIZE_64 || remaining > TASK_SIZE_64 - addr ||
	    !access_ok(buffer, remaining))
		return -EINVAL;
	if (!remaining)
		return 0;
	target = find_get_pid(request->pid);
	task = get_pid_task(target, PIDTYPE_PID);
	put_pid(target);
	if (!task)
		return -ESRCH;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ESRCH;
	bounce = session_bounce ? session_bounce : kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce) {
		mmput(mm);
		return -ENOMEM;
	}
	/* Keep the VMA/page-table read lock across the transfer. This avoids one
	 * mmap_lock acquire/release pair per page while preserving a bounded
	 * critical section (the ioctl limit is 16 MiB). */
	mmap_read_lock(mm);
	while (remaining) {
		offset = offset_in_page(addr);
		chunk = min(remaining, PAGE_SIZE - offset);
		if (write && copy_from_user(bounce, buffer, chunk)) {
			error = -EFAULT;
			break;
		}
		page = lk1337_resolve_page(mm, addr, write, &error, &cached_vma);
		if (!page)
			break;
		error = 0;
		mapped = kmap(page);
		if (write) {
			memcpy(mapped + offset, bounce, chunk);
			flush_dcache_page(page);
			/* This interface is used for data movement; avoid the expensive
			 * instruction-cache flush on every page. Code patching has its own
			 * hook_write_range path which performs the required I-cache sync. */
		} else {
			memcpy(bounce, mapped + offset, chunk);
		}
		kunmap(page);
		if (write)
			set_page_dirty_lock(page);
		put_page(page);
		if (!write && copy_to_user(buffer, bounce, chunk)) {
			error = -EFAULT;
			break;
		}
		remaining -= chunk;
		buffer += chunk;
		addr += chunk;
	}
	mmap_read_unlock(mm);
	if (!session_bounce)
		kfree(bounce);
	mmput(mm);
	return error;
}

#endif
