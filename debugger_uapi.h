#ifndef LK1337_UAPI_H
#define LK1337_UAPI_H

#include <linux/types.h>

#define LK1337_READ 601
#define LK1337_WRITE 602
#define LK1337_BASE 603
#define LK1337_BP_CREATE 610
#define LK1337_BP_REMOVE 611
#define LK1337_BP_LEGACY_HITS 612
#define LK1337_BP_LEGACY_MODIFY 613
#define LK1337_BP_CLEAR 614
#define LK1337_BP_TEMPLATE 615
#define LK1337_BP_HITS 616
#define LK1337_BP_PAUSE 617
#define LK1337_BP_RESUME 618
#define LK1337_GYRO_CONFIG 620
#define LK1337_MAPS_FILTER_ADD 621
#define LK1337_MAPS_FILTER_REMOVE 622
#define LK1337_MAPS_FILTER_CLEAR 623
#define LK1337_MAPS_FILTER_ENABLE 624
#define LK1337_MAPS_FILTER_ADD_PID 625
#define LK1337_MAPS_FILTER_REMOVE_PID 626
#define LK1337_MAPS_FILTER_CLEAR_PID 627
#define LK1337_MAPS_FILTER_SET_ALL 628
#define LK1337_TTBR_SETUP 630
#define LK1337_TTBR_UPDATE 631
#define LK1337_TTBR_SET_EXECUTOR 632
#define LK1337_TTBR_CLEAR_EXECUTOR 633
#define LK1337_TTBR_DESTROY 634
#define LK1337_TTBR_QUERY 635
#define LK1337_BT_MAX 32
#define LK1337_BP_F_DETAIL  (1U << 0)
#define LK1337_BP_F_BACKTRACE (1U << 1)
#define LK1337_GYRO_MASK_GYRO (1u << 0)
#define LK1337_GYRO_MASK_UNCAL (1u << 1)
#define LK1337_GYRO_MASK_ALL (LK1337_GYRO_MASK_GYRO | LK1337_GYRO_MASK_UNCAL)
#define LK1337_ABI_VERSION 3
#define LK1337_FP_VALID 1
#define LK1337_FP_CHANGED 2
#define LK1337_ONESHOT 1
#define LK1337_DRAIN 1
#define LK1337_BOOTSTRAP 0x4b530001U
#define LK1337_BOOTSTRAP_MAGIC 0x42464946U


struct lk1337_bootstrap {
	__u32 magic;
	__s32 fd;
};

struct lk1337_memory {
	__s32 pid;
	__u32 reserved;
	__u64 addr;
	__u64 buffer;
	__u64 size;
};

struct lk1337_base {
	__s32 pid;
	__u32 reserved;
	__u64 name;
	__u64 base;
};

struct lk1337_create {
	__u64 addr;
	__s32 type;
	__s32 len;
	__s32 pid;
	__s32 max_records;
	__s32 bp_id;
	__u32 flags;
};

struct lk1337_id { __s32 bp_id; };

struct lk1337_vector { __u64 low; __u64 high; };

struct lk1337_snapshot {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
	struct lk1337_vector vregs[32];
	__u32 fpsr;
	__u32 fpcr;
};

struct lk1337_hit {
	__u64 sequence;
	__u64 timestamp;
	__u64 addr;
	__s32 pid;
	__s32 tid;
	__u32 flags;
	__u32 reserved;
	struct lk1337_snapshot before;
	struct lk1337_snapshot after;
	__u32 bt_count;
	__u32 bt_flags;
	__u64 backtrace[LK1337_BT_MAX];
};

struct lk1337_template {
	__s32 bp_id;
	__u32 flags;
	__u64 gp_mask;
	__u32 fp_mask;
	__u32 control_mask;
	struct lk1337_snapshot values;
};

struct lk1337_hits {
	__s32 bp_id;
	__u32 flags;
	__u64 buffer;
	__u32 capacity;
	__u32 count;
	__u64 total;
	__u64 dropped;
	__u64 fp_unavailable;
};

struct lk1337_legacy_hits {
	__s32 bp_id;
	__u32 reserved;
	__u64 buffer;
	__s32 max_count;
	__s32 actual_count;
};

struct lk1337_legacy_modify {
	__s32 bp_id;
	__s32 record_index;
	__s32 reg_index;
	__u32 reserved;
	__u64 value;
};

/* Gyro packet adjustment: enable, type mask, and additive float bit patterns. */
struct lk1337_gyro_config {
	__u32 enable;
	__u32 type_mask;
	__u32 add0;
	__u32 add1;
};

/* Maps filter: hide injected modules from /proc/pid/maps */
struct lk1337_maps_filter {
	__u32 enable;  /* 0=disable, 1=enable */
	__u32 reserved;
	char pattern[256];  /* pattern to add/remove */
};

/* Maps filter PID control */
struct lk1337_maps_filter_pid {
	__s32 pid;     /* target PID to filter */
	__u32 enable;  /* for SET_ALL: 0=per-pid mode, 1=global mode */
};

struct lk1337_ttbr_setup {
	__u64 start;
	__u64 end;
	__u64 alter_mem;
	__s32 source_pid;
	__s32 executor_tid;
	__u32 flags;
	__s32 view_id;
};

struct lk1337_ttbr_update {
	__s32 view_id;
	__u32 flags;
	__u64 start;
	__u64 end;
	__u64 alter_mem;
};

struct lk1337_ttbr_executor {
	__s32 view_id;
	__s32 executor_tid;
};

struct lk1337_ttbr_query {
	__s32 view_id;
	__u32 flags;
	__s32 source_pid;
	__s32 executor_tid;
	__u64 start;
	__u64 end;
	__u64 size;
	__u64 nr_pages;
	__u64 source_pgd_phys;
	__u64 alter_pgd_phys;
	__u64 source_asid;
	__u64 alter_asid;
	__u64 real_phys_array;
	__u64 alter_phys_array;
	__u32 page_capacity;
	__u32 page_count;
};

#endif
