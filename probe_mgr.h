/* SPDX-License-Identifier: GPL-2.0 */
/*
 * lk1337 lazy probe manager.
 *
 * A resident kprobe is not free.  Measured on the target (xaga, 5.10.226
 * vendor kernel, see bench/) one kprobe invocation adds ~200-500 ns to
 * whichever kernel function carries it, and lk1337 used to keep eleven of them
 * installed for the whole module lifetime -- including one on __schedule,
 * which every context switch on the system walks through.  That is the only
 * footprint an unprivileged process can measure without any SELinux
 * interaction: a matched-pair syscall timing differential needs no root, no
 * debugfs and no kernel address.
 *
 * So no probe is registered until the feature that needs it is actually in use,
 * and it is removed again when the last user goes away.  A module that is
 * loaded but idle then has zero feature probes in the kernel text.
 *
 * Rules for callers:
 *   - lk1337_probe_use()/lk1337_probe_release() may sleep (register_kprobe()
 *     takes kprobe_mutex and patches text), so they must be called from
 *     process context, never from a probe handler, a spinlock or an IRQ.
 *   - lk1337_probe_busy() is a lock-free single-word read and is safe from a
 *     probe handler.
 *   - A handler must keep working after its probe is gone: the target function
 *     can still be inside the handler on another CPU while the last user tears
 *     the probe down.
 *
 * Two traps this file exists to avoid, both observed on the target kernel:
 *
 *   1. unregister_kprobe() leaves the caller's struct carrying the old address.
 *      Re-registering it without clearing it makes the core's
 *      check_kprobe_rereg() return -EINVAL, so the probe silently never comes
 *      back.  lk1337_probe_arm_impl() memsets the struct every time.
 *
 *   2. A probe that is *disabled* when the module unloads is not cleaned up by
 *      the core's module notifier, so its hash entry survives with a pointer
 *      into the freed module and every later register_kprobe() at that address
 *      fails with -EINVAL.  This manager therefore only ever has a probe fully
 *      registered or fully unregistered; it never leaves one disabled.
 *
 * This header is included by several translation units (entry.c owns the
 * bootstrap and gyro hooks, ttbr_view.c the scheduler hooks, memwatch.c the
 * procfs hooks, uxn_breakpoint.h the mprotect hooks).  The state and the
 * implementation must exist exactly once: entry.c defines LK1337_PROBE_IMPL
 * before including this file, and every other user gets only the declarations.
 */
#ifndef LK1337_PROBE_MGR_H
#define LK1337_PROBE_MGR_H

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>

struct lk1337_probe {
	const char *target;		/* symbol name, for the log	*/
	const char *feature;		/* owner, for the log		*/
	kprobe_pre_handler_t pre;
	kprobe_post_handler_t post;
	struct kprobe kp;
	atomic_t refs;			/* feature activation count	*/
	bool should_exist;		/* probe is in the kernel now	*/
};

#define LK1337_PROBE(_target, _feature, _pre, _post)			\
	{								\
		.target = (_target),					\
		.feature = (_feature),					\
		.pre = (_pre),						\
		.post = (_post),					\
		.refs = ATOMIC_INIT(0),					\
	}

extern struct mutex lk1337_probe_mutex;
extern bool lk1337_probe_ready;

int lk1337_probe_mgr_init(void);
int lk1337_probe_arm_impl(struct lk1337_probe *p);
void lk1337_probe_disarm_impl(struct lk1337_probe *p);
int lk1337_probe_use_impl(struct lk1337_probe *p);
void lk1337_probe_release_impl(struct lk1337_probe *p);

static __maybe_unused int lk1337_probe_manager_init(void)
{
	/* Nothing to resolve: register_kprobe()/unregister_kprobe() are
	 * exported normally.  Kept as an explicit step so the module fails
	 * loudly rather than silently losing hooks. */
	return lk1337_probe_mgr_init();
}

static __maybe_unused int lk1337_probe_arm(struct lk1337_probe *p)
{
	return lk1337_probe_arm_impl(p);
}

static __maybe_unused void lk1337_probe_disarm(struct lk1337_probe *p)
{
	lk1337_probe_disarm_impl(p);
}

/* Number of features currently using this probe (0 when idle). */
static __maybe_unused int lk1337_probe_refs(struct lk1337_probe *p)
{
	return atomic_read(&p->refs);
}

static __maybe_unused bool lk1337_probe_busy(struct lk1337_probe *p)
{
	return READ_ONCE(p->should_exist);
}

static __maybe_unused int lk1337_probe_use(struct lk1337_probe *p)
{
	return lk1337_probe_use_impl(p);
}

static __maybe_unused void lk1337_probe_release(struct lk1337_probe *p)
{
	lk1337_probe_release_impl(p);
}

#ifdef LK1337_PROBE_IMPL
/*
 * Implementation.  entry.c defines LK1337_PROBE_IMPL before including this
 * file so these symbols exist exactly once in the module.
 */
DEFINE_MUTEX(lk1337_probe_mutex);
bool lk1337_probe_ready;

int lk1337_probe_mgr_init(void)
{
	lk1337_probe_ready = true;
	return 0;
}

/*
 * Clear the whole struct before every registration: the previous incarnation's
 * address and flags must not survive into the next one, or the core's
 * check_kprobe_rereg() rejects it with -EINVAL.
 */
int lk1337_probe_arm_impl(struct lk1337_probe *p)
{
	int error;

	if (p->should_exist)
		return 0;
	memset(&p->kp, 0, sizeof(p->kp));
	p->kp.symbol_name = p->target;
	p->kp.pre_handler = p->pre;
	p->kp.post_handler = p->post;
	error = register_kprobe(&p->kp);
	if (error)
		return error;
	p->should_exist = true;
	pr_info("probe %s (%s) installed\n", p->target, p->feature);
	return 0;
}

/*
 * Unregister, never merely disable.  unregister_kprobe() takes the breakpoint
 * out of the text and drops the hash entry in one step; a probe that is merely
 * disabled when the module unloads is skipped by the core's module notifier, so
 * its entry would survive with a pointer into the freed module and every later
 * register_kprobe() at that address would fail with -EINVAL.
 */
void lk1337_probe_disarm_impl(struct lk1337_probe *p)
{
	if (!p->should_exist)
		return;
	unregister_kprobe(&p->kp);
	p->should_exist = false;
	pr_info("probe %s (%s) removed\n", p->target, p->feature);
}

int lk1337_probe_use_impl(struct lk1337_probe *p)
{
	int error = 0;

	if (!lk1337_probe_ready)
		return -ENOENT;
	mutex_lock(&lk1337_probe_mutex);
	if (atomic_inc_return(&p->refs) == 1)
		error = lk1337_probe_arm_impl(p);
	if (error)
		atomic_dec(&p->refs);
	mutex_unlock(&lk1337_probe_mutex);
	if (error)
		pr_warn("probe %s (%s) unavailable: %d\n", p->target,
			p->feature, error);
	return error;
}

void lk1337_probe_release_impl(struct lk1337_probe *p)
{
	if (!lk1337_probe_ready)
		return;
	mutex_lock(&lk1337_probe_mutex);
	if (atomic_read(&p->refs) > 0 && atomic_dec_and_test(&p->refs))
		lk1337_probe_disarm_impl(p);
	mutex_unlock(&lk1337_probe_mutex);
}
#endif /* LK1337_PROBE_IMPL */

#endif /* LK1337_PROBE_MGR_H */
