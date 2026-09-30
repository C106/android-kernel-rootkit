#ifndef LK1337_KCOMPAT_H
#define LK1337_KCOMPAT_H

#include <linux/version.h>
#include <linux/mm.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
# define LK1337_VMA_ITER_NEW 1
#else
# define LK1337_VMA_ITER_NEW 0
#endif

/* bio_alloc() gained a block-device and bioset argument in 6.1. */
static inline struct bio *lk1337_bio_alloc(struct block_device *bdev,
						gfp_t gfp, unsigned int nr_vecs)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	return bio_alloc(bdev, nr_vecs, 0, gfp);
#else
	struct bio *bio = bio_alloc(gfp, nr_vecs);
	if (bio && bdev)
		bio_set_dev(bio, bdev);
	return bio;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
# define LK1337_VMA_ITER(name, mm, start) \
	VMA_ITERATOR(name, mm, start)
# define LK1337_FOR_EACH_VMA(vmi, vma) for_each_vma(vmi, vma)
#else
# define LK1337_VMA_ITER(name, mm, start) \
	struct vm_area_struct *name = (mm)->mmap
# define LK1337_FOR_EACH_VMA(vmi, vma) \
	for ((vma) = (vmi); (vma); (vma) = (vma)->vm_next)
#endif

#ifdef LK1337_HAS_THREAD_SVE_VL
# define LK1337_SVE_VL(task) thread_get_sve_vl(&(task)->thread)
#else
# define LK1337_SVE_VL(task) ((task)->thread.sve_vl)
#endif

/* Probe these independently: Android backports can change one callback ABI
 * without changing the other. Exact types matter to the kernel's CFI. */
#ifdef LK1337_STEP_ESR_ULONG
# define LK1337_STEP_ESR_T unsigned long
#else
# define LK1337_STEP_ESR_T unsigned int
#endif

#ifdef LK1337_FAULT_ESR_ULONG
# define LK1337_FAULT_ESR_T unsigned long
#else
# define LK1337_FAULT_ESR_T unsigned int
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
/* Targeted flush helpers pull in an unexported secondary-TLB notifier. */
# define LK1337_UXN_FLUSH_TLB_MM(mm) flush_tlb_all()
# define LK1337_UXN_FLUSH_TLB_PAGE(vma, addr) flush_tlb_all()
#else
# define LK1337_UXN_FLUSH_TLB_MM(mm) flush_tlb_mm(mm)
# define LK1337_UXN_FLUSH_TLB_PAGE(vma, addr) flush_tlb_page(vma, addr)
#endif

#ifndef __CFI_ADDRESSABLE
# define __CFI_ADDRESSABLE(fn)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
# define LK1337_CFI_ADDRESSABLE(fn) __CFI_ADDRESSABLE(fn, )
#else
# define LK1337_CFI_ADDRESSABLE(fn) __CFI_ADDRESSABLE(fn)
#endif

#endif
