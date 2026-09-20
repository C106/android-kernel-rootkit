#ifndef LK1337_MEMORY_H
#define LK1337_MEMORY_H

#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

/*
 * Read a swapped-out page straight from the swap device into a page of our
 * own, so that nothing is faulted back into the target: its page tables, its
 * RSS and the zram slot all stay untouched. The swap device on Android is
 * zram, whose block layer already decompresses, expands same-filled pages and
 * hides whichever compression backend the kernel was built with.
 *
 * Addressing the compressed object by hand (zram->table -> zs_map_object ->
 * zcomp_decompress) is not an option: zs_map_object, zcomp_decompress and
 * crypto_alloc_acomp are not exported, and struct zram / zram_table_entry live
 * in a driver-private header. Going through the block device needs only
 * exported symbols and stays correct across vendor differences.
 *
 * The caller owns the returned page (put_page). Reads only: writing a swapped
 * page still needs a real fault (GUP with FOLL_WRITE) to preserve COW.
 */
static struct page *lk1337_read_swap_page(swp_entry_t entry)
{
	struct swap_info_struct *si = swp_swap_info(entry);
	struct bio *bio;
	struct page *page;

	/*
	 * swp_swap_info() returns the swap_info_struct without taking a
	 * reference (get_swap_device() is not exported). The entry came from a
	 * live PTE and we hold mmap_read_lock, so the area can only go away
	 * through swapoff, which would swap this page in first.
	 */
	if (!si || !si->bdev)
		return NULL;	/* swap file instead of a block device */
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return NULL;
	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio) {
		__free_pages(page, 0);
		return NULL;
	}
	bio_set_dev(bio, si->bdev);
	/* zram's logical block size is PAGE_SIZE, so the sector is offset << 3. */
	bio->bi_iter.bi_sector = (sector_t)swp_offset(entry) << (PAGE_SHIFT - 9);
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	if (bio_add_page(bio, page, PAGE_SIZE, 0) != PAGE_SIZE)
		goto fail;
	if (submit_bio_wait(bio))
		goto fail;
	bio_put(bio);
	return page;
fail:
	bio_put(bio);
	__free_pages(page, 0);
	return NULL;
}

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
	swp_entry_t swap;
	bool have_swap = false;

	*error = -EFAULT;
	vma = *cached_vma;
	if (!vma || addr < vma->vm_start || addr >= vma->vm_end) {
		vma = find_vma(mm, addr);
		*cached_vma = vma;
	}
	if (!vma || addr < vma->vm_start || vma->vm_flags & (VM_IO | VM_PFNMAP))
		return NULL;
	/*
	 * Permission check, aligned with GUP's FOLL_FORCE rule
	 * (mm/gup.c:check_vma_flags): a read is still allowed on a mapping that
	 * lacks VM_READ as long as VM_MAYREAD is set. VM_READ is a software flag
	 * only -- arm64 maps a write-only private VMA with PAGE_READONLY
	 * (PTE_USER|PTE_RDONLY, AP[2:1] = "Read-only, EL0"), which reads fine
	 * and only faults on writes.
	 *
	 * Measured on a real target: libUE4.so's 14.7 MB .bss is mapped
	 * PROT_WRITE-only (the only "-w-p" mapping in the process, named
	 * [anon:.bss]) as anti-read hardening, so every global in it (GWorld,
	 * GNames, ...) was rejected with -EACCES regardless of whether its page
	 * was resident. /proc/pid/mem reads it because FOLL_FORCE only needs
	 * VM_MAYREAD. Writes still require a genuinely writable VMA.
	 */
	if (!(vma->vm_flags & (write ? VM_WRITE : VM_READ)) &&
	    (write || !(vma->vm_flags & VM_MAYREAD))) {
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
		if (!pmd_present(middle) || pmd_protnone(middle) ||
		    pmd_devmap(middle) || (write && !pmd_write(middle)))
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
	/*
	 * PTE acceptance. PROT_NONE has to stay rejected explicitly: arm64 keeps
	 * such a PTE "present" (PTE_PROT_NONE set, PTE_VALID clear) and still
	 * encodes a valid PFN, so now that the VMA test above accepts write-only
	 * mappings, dropping this check would turn PROT_NONE into readable
	 * memory.
	 *
	 * PTE_SPECIAL is accepted on purpose: it marks the shared zero page and
	 * KSM pages (mm/memory.c:3929, mm/ksm.c:1160). Mapping the zero page
	 * yields the zeros an untouched anonymous page is defined to hold, and a
	 * KSM page is ordinary anonymous data. Device mappings stay excluded via
	 * pte_devmap() plus pfn_valid().
	 */
	if (pte_present(entry) && !pte_protnone(entry) && !pte_devmap(entry) &&
	    (!write || pte_write(entry)) && pfn_valid(pte_pfn(entry))) {
		page = pfn_to_page(pte_pfn(entry));
		get_page(page);
	} else if (!write && is_swap_pte(entry)) {
		/*
		 * Swapped out. Only the entry is taken here: the block read
		 * below sleeps, so the PTE lock has to be dropped first.
		 */
		swap = pte_to_swp_entry(entry);
		have_swap = true;
	}
	pte_unmap_unlock(pte, lock);
	if (have_swap)
		page = lk1337_read_swap_page(swap);
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
