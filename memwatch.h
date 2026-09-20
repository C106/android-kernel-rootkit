#ifndef MEMWATCH_H
#define MEMWATCH_H

#include <linux/types.h>
#include <linux/kernel.h>
#include "memwatch_uapi.h"

/*
 * Process-hiding feature merged into lk1337.ko. The implementation and all
 * module-level state live in memwatch.c; the session fd created by either
 * bootstrap command (LK1337_BOOTSTRAP or MW_BOOTSTRAP) dispatches these
 * commands through lk1337_dispatch().
 */

/* True for the MW_HIDE_* command range, so the caller can route it. */
bool lk1337_memwatch_command(unsigned int cmd);

/* Handle one MW_HIDE_* command. Caller has already checked root. */
long lk1337_memwatch_dispatch(unsigned int cmd, void __user *arg);

/*
 * Register the procfs/signal kprobes. Returns -ENOENT when no hiding hook is
 * available; the caller keeps loading lk1337 and logs the degradation.
 */
int lk1337_memwatch_init(void);
void lk1337_memwatch_exit(void);

#endif
