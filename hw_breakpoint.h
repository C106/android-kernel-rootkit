#ifndef LK1337_HW_H
#define LK1337_HW_H

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/vmalloc.h>
#include "fpsimd_state.h"

struct lk1337_breakpoint {
	struct list_head node;
	struct perf_event *event;
	struct lk1337_hit *ring;
	struct lk1337_template change;
	raw_spinlock_t lock;
	u64 total;
	u64 dropped;
	u64 fp_unavailable;
	unsigned int capacity;
	unsigned int head;
	unsigned int count;
	int id;
	u32 flags;
};

struct lk1337_session {
	struct mutex lock;
	struct list_head breakpoints;
	struct list_head ttbr_views;
	void *memory_bounce;
	int next_id;
};

static void lk1337_capture_user_bt(struct lk1337_hit *hit, struct pt_regs *regs)
{
	u64 fp = regs->regs[29], frame[2];
	unsigned int n = 0;
	if (regs->pc < TASK_SIZE_64) hit->backtrace[n++] = regs->pc;
	if (regs->regs[30] < TASK_SIZE_64 && n < LK1337_BT_MAX)
		hit->backtrace[n++] = regs->regs[30] - 4;
	while (n < LK1337_BT_MAX && fp && !(fp & 15) && fp < TASK_SIZE_64 - 16) {
		if (copy_from_user(frame, (void __user *)(uintptr_t)fp, sizeof(frame))) {
			hit->bt_flags |= 1; break;
		}
		if (!frame[0] || frame[0] <= fp || (frame[0] & 15) || frame[0] >= TASK_SIZE_64) break;
		if (frame[1] >= TASK_SIZE_64) break;
		hit->backtrace[n++] = frame[1] - 4;
		fp = frame[0];
	}
	hit->bt_count = n;
}

static void lk1337_snapshot_gp(struct lk1337_snapshot *snapshot, struct pt_regs *regs)
{
	memcpy(snapshot->regs, regs->regs, sizeof(snapshot->regs));
	snapshot->sp = regs->sp;
	snapshot->pc = regs->pc;
	snapshot->pstate = regs->pstate;
}

static void lk1337_overflow(struct perf_event *event, struct perf_sample_data *data,
		       struct pt_regs *regs)
{
	struct lk1337_breakpoint *bp = event->overflow_handler_context;
	struct lk1337_template *change = &bp->change;
	struct lk1337_hit *hit;
	unsigned long flags;
	unsigned int index;
	bool fp_valid;

	if (!user_mode(regs))
		return;
	if (!(bp->flags & LK1337_BP_F_DETAIL)) {
		raw_spin_lock_irqsave(&bp->lock, flags);
		bp->total++;
		for (index = 0; index < 31; index++)
			if (change->gp_mask & BIT_ULL(index)) regs->regs[index] = change->values.regs[index];
		if (change->gp_mask & BIT_ULL(31)) regs->sp = change->values.sp;
		if (change->gp_mask & BIT_ULL(32)) regs->pc = change->values.pc;
		if (change->gp_mask & BIT_ULL(33)) regs->pstate = (regs->pstate & ~PSR_f) | (change->values.pstate & PSR_f);
		if (change->fp_mask || change->control_mask) lk1337_fp_stage_template(change);
		if (change->flags & LK1337_ONESHOT) change->gp_mask = change->fp_mask = change->control_mask = 0;
		raw_spin_unlock_irqrestore(&bp->lock, flags);
		return;
	}
	raw_spin_lock_irqsave(&bp->lock, flags);
	if (bp->count == bp->capacity) {
		bp->head = (bp->head + 1) % bp->capacity;
		bp->count--;
		bp->dropped++;
	}
	index = (bp->head + bp->count++) % bp->capacity;
	hit = &bp->ring[index];
	memset(hit, 0, sizeof(*hit));
	hit->sequence = ++bp->total;
	hit->timestamp = ktime_get_ns();
	hit->addr = counter_arch_bp(event)->trigger;
	hit->pid = task_tgid_vnr(current);
	hit->tid = task_pid_vnr(current);
	if (bp->flags & LK1337_BP_F_BACKTRACE)
		lk1337_capture_user_bt(hit, regs);
	lk1337_snapshot_gp(&hit->before, regs);
	fp_valid = lk1337_fp_capture(&hit->before);
	if (fp_valid)
		hit->flags |= LK1337_FP_VALID;
	else
		bp->fp_unavailable++;
	hit->after = hit->before;
	for (index = 0; index < 31; index++)
		if (change->gp_mask & BIT_ULL(index))
			regs->regs[index] = change->values.regs[index];
	if (change->gp_mask & BIT_ULL(31))
		regs->sp = change->values.sp;
	if (change->gp_mask & BIT_ULL(32))
		regs->pc = change->values.pc;
	if (change->gp_mask & BIT_ULL(33))
		regs->pstate = (regs->pstate & ~PSR_f) |
			       (change->values.pstate & PSR_f);
	/* Do not advance or emulate PC here. The ARM64 perf breakpoint handler
	 * sees orig_overflow_handler and performs native single-step: it disables
	 * EL0 breakpoints, returns with PC unchanged, executes the trapped
	 * instruction in place, then reinstalls all suspended breakpoints. */
	lk1337_snapshot_gp(&hit->after, regs);
	if (change->fp_mask || change->control_mask) {
		for (index = 0; index < 32; index++)
			if (change->fp_mask & BIT(index))
				hit->after.vregs[index] = change->values.vregs[index];
		if (change->control_mask & 1)
			hit->after.fpsr = change->values.fpsr;
		if (change->control_mask & 2)
			hit->after.fpcr = change->values.fpcr;
		if (lk1337_fp_stage_template(change))
			hit->flags |= LK1337_FP_CHANGED;
	}
	if ((change->flags & LK1337_ONESHOT) &&
	    (fp_valid || !(change->fp_mask || change->control_mask))) {
		change->gp_mask = 0;
		change->fp_mask = 0;
		change->control_mask = 0;
	}
	raw_spin_unlock_irqrestore(&bp->lock, flags);
}

static struct lk1337_breakpoint *lk1337_find(struct lk1337_session *session, int id)
{
	struct lk1337_breakpoint *bp;

	list_for_each_entry(bp, &session->breakpoints, node)
		if (bp->id == id)
			return bp;
	return NULL;
}

static int lk1337_create_bp(struct lk1337_session *session, struct lk1337_create *request)
{
	struct perf_event_attr attr;
	struct lk1337_breakpoint *bp;
	struct task_struct *task;
	struct pid *target;
	int error;
	static const int types[] = {
		HW_BREAKPOINT_X, HW_BREAKPOINT_R, HW_BREAKPOINT_W, HW_BREAKPOINT_RW
	};

	if (request->type < 0 || request->type > 3 || request->pid < 0 ||
	    (request->flags & ~(LK1337_BP_F_DETAIL | LK1337_BP_F_BACKTRACE)) ||
	    ((request->flags & LK1337_BP_F_BACKTRACE) && !(request->flags & LK1337_BP_F_DETAIL)) ||
	    !request->addr || request->addr >= TASK_SIZE_64 ||
	    request->max_records < 0 || request->max_records > 4096 ||
	    (request->len != 1 && request->len != 2 &&
	     request->len != 4 && request->len != 8) ||
	    (request->type == 0 && (request->len != 4 || request->addr & 3)))
		return -EINVAL;
	if (session->next_id == INT_MAX)
		return -ENOSPC;
	target = find_get_pid(request->pid ? request->pid : task_pid_vnr(current));
	if (!target)
		return -ESRCH;
	task = get_pid_task(target, PIDTYPE_PID);
	put_pid(target);
	if (!task)
		return -ESRCH;
	if (!task->mm || is_compat_thread(task_thread_info(task))) {
		put_task_struct(task);
		return -EOPNOTSUPP;
	}
	bp = kzalloc(sizeof(*bp), GFP_KERNEL);
	if (!bp) {
		put_task_struct(task);
		return -ENOMEM;
	}
	bp->capacity = request->max_records ? request->max_records : 256;
	bp->flags = request->flags;
	bp->ring = kvcalloc(bp->capacity, sizeof(*bp->ring), GFP_KERNEL);
	if (!bp->ring) {
		error = -ENOMEM;
		goto fail;
	}
	raw_spin_lock_init(&bp->lock);
	hw_breakpoint_init(&attr);
	attr.bp_addr = request->addr;
	attr.bp_len = request->len;
	attr.bp_type = types[request->type];
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	attr.disabled = 1;
	bp->event = perf_event_create_kernel_counter(&attr, -1, task, NULL, NULL);
	if (IS_ERR(bp->event)) {
		error = PTR_ERR(bp->event);
		goto fail;
	}
#ifdef CONFIG_BPF_SYSCALL
	/* The counter was created disabled with a NULL callback, so perf chose
	 * its default output handler. Preserve that identity before installing
	 * ours: ARM64 uses uses_default_overflow_handler() to request native
	 * stepping even with a custom callback. This is a GKI-version dependency,
	 * not a request to invoke the default output handler or attach BPF. */
	bp->event->orig_overflow_handler = bp->event->overflow_handler;
	bp->event->overflow_handler_context = bp;
	bp->event->overflow_handler = lk1337_overflow;
#else
	perf_event_release_kernel(bp->event);
	error = -EOPNOTSUPP;
	goto fail;
#endif
	bp->id = session->next_id++;
	list_add_tail(&bp->node, &session->breakpoints);
	request->bp_id = bp->id;
	perf_event_enable(bp->event);
	put_task_struct(task);
	return 0;
fail:
	kvfree(bp->ring);
	kfree(bp);
	put_task_struct(task);
	return error;
}

static void lk1337_destroy_bp(struct lk1337_breakpoint *bp)
{
	list_del(&bp->node);
	perf_event_release_kernel(bp->event);
	kvfree(bp->ring);
	kfree(bp);
}

static int lk1337_set_template(struct lk1337_breakpoint *bp, struct lk1337_template *change)
{
	unsigned long flags;

	if ((change->gp_mask >> 34) || change->control_mask & ~3U ||
	    change->flags & ~LK1337_ONESHOT)
		return -EINVAL;
	if ((change->gp_mask & BIT_ULL(31)) &&
	    (change->values.sp >= TASK_SIZE_64 || change->values.sp & 15))
		return -EINVAL;
	if ((change->gp_mask & BIT_ULL(32)) &&
	    (!change->values.pc || change->values.pc >= TASK_SIZE_64 ||
	     change->values.pc & 3))
		return -EINVAL;
	raw_spin_lock_irqsave(&bp->lock, flags);
	bp->change = *change;
	raw_spin_unlock_irqrestore(&bp->lock, flags);
	return 0;
}

static int lk1337_read_hits(struct lk1337_breakpoint *bp, struct lk1337_hits *request)
{
	struct lk1337_hit *copy;
	unsigned long flags;
	unsigned int index, count;
	u64 last_sequence = 0;
	int error = 0;

	if (request->capacity > 4096 || request->flags & ~LK1337_DRAIN)
		return -EINVAL;
	count = min(request->capacity, bp->capacity);
	copy = kvmalloc_array(count, sizeof(*copy), GFP_KERNEL);
	if (count && !copy)
		return -ENOMEM;
	raw_spin_lock_irqsave(&bp->lock, flags);
	count = min(count, bp->count);
	for (index = 0; index < count; index++)
		copy[index] = bp->ring[(bp->head + index) % bp->capacity];
	request->count = count;
	request->total = bp->total;
	request->dropped = bp->dropped;
	request->fp_unavailable = bp->fp_unavailable;
	if (count)
		last_sequence = copy[count - 1].sequence;
	raw_spin_unlock_irqrestore(&bp->lock, flags);
	if (count && copy_to_user(u64_to_user_ptr(request->buffer), copy,
				  count * sizeof(*copy))) {
		error = -EFAULT;
		goto out;
	}
	if (count && request->flags & LK1337_DRAIN) {
		raw_spin_lock_irqsave(&bp->lock, flags);
		while (bp->count && bp->ring[bp->head].sequence <= last_sequence) {
			bp->head = (bp->head + 1) % bp->capacity;
			bp->count--;
		}
		raw_spin_unlock_irqrestore(&bp->lock, flags);
	}
out:
	kvfree(copy);
	return error;
}

#endif
