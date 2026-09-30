#define pr_fmt(fmt) "lk1337: " fmt

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sizes.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/kprobes.h>
#include <linux/anon_inodes.h>
#include <linux/task_work.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

/*
 * The probe manager's own implementation (mutex, state, register/unregister
 * helpers) is instantiated here and only here.  It has to be defined before the
 * first include of probe_mgr.h, which arrives transitively through
 * uxn_breakpoint.h below.
 */
#define LK1337_PROBE_IMPL
#include "debugger_uapi.h"
#include "memory.h"
#include "process.h"
#include "hw_breakpoint.h"
#include "uxn_breakpoint.h"
#include "maps_filter.h"
#include "ttbr_view.h"
#include "memwatch.h"
#include "probe_mgr.h"

struct lk1337_legacy_snapshot {
	struct pt_regs regs;
	__uint128_t vregs[32];
	u32 fpsr;
	u32 fpcr;
	unsigned long pc;
	unsigned long pstate;
	u64 timestamp;
};

struct lk1337_legacy_record {
	unsigned long addr;
	pid_t pid;
	pid_t tid;
	struct lk1337_legacy_snapshot snap;
	u64 hit_count;
	struct list_head list;
};

static bool lk1337_root(void)
{
	const struct cred *cred = current_cred();

	return uid_eq(cred->uid, GLOBAL_ROOT_UID) &&
	       uid_eq(cred->euid, GLOBAL_ROOT_UID) &&
	       uid_eq(cred->suid, GLOBAL_ROOT_UID);
}


/* Both bootstraps hand back the same session fd: memwatch is part of this
 * module now and its MW_HIDE_* commands are dispatched by lk1337_dispatch(). */
static bool lk1337_hook_command(unsigned int cmd)
{
	return cmd == LK1337_BOOTSTRAP || cmd == MW_BOOTSTRAP;
}

struct lk1337_bootstrap_work {
	struct callback_head callback;
	struct lk1337_bootstrap __user *request;
};

typedef int (*lk1337_task_work_add_t)(struct task_struct *, struct callback_head *,
					 enum task_work_notify_mode);
static lk1337_task_work_add_t lk1337_task_work_add;

static __nocfi int lk1337_add_task_work(struct task_struct *task,
					struct callback_head *work,
					enum task_work_notify_mode mode)
{
	return lk1337_task_work_add(task, work, mode);
}

static const struct file_operations lk1337_fops;
static struct lk1337_probe lk1337_ioctl_probe;

/* Optional sendto gyro stream transformer. Records are 0x68 bytes; type at
 * +8, two float bit-patterns at +24/+28.
 *
 * Only sends issued by system_server are rewritten: the sensor service lives
 * there (thread "SensorService"), so filtering on the sender leaves every other
 * process's sendto() completely untouched.
 */
#define LK1337_GYRO_SERVER_COMM "system_server"
#define LK1337_GYRO_LOG_SAMPLES 6
#define LK1337_GYRO_MAX_PACKET 0x200000
/* Disabled until userspace supplies an explicit configuration via ioctl. */
static atomic_t gyro_enabled = ATOMIC_INIT(0);
static pid_t gyro_server_tgid;
static u32 gyro_mask;
static u32 gyro_add0, gyro_add1;
static DEFINE_MUTEX(gyro_lock);
/* The sendto pre-handler cannot sleep. Allocate the scratch buffer while
 * enabling the feature and serialize concurrent transforms with a raw lock. */
static u8 *gyro_buffer;
static size_t gyro_buffer_size;
static DEFINE_RAW_SPINLOCK(gyro_buffer_lock);
/* How many rewritten records to report in dmesg after an enable; lets a user
 * confirm the transformation without flooding the log. */
static atomic_t gyro_log_budget = ATOMIC_INIT(0);

/* system_server's thread-group id, or 0 when it is not running. */
static pid_t lk1337_gyro_find_server(void)
{
	struct task_struct *task, *found = NULL;
	pid_t tgid = 0;

	rcu_read_lock();
	for_each_process(task) {
		if (!strcmp(task->comm, LK1337_GYRO_SERVER_COMM)) {
			found = task;
			break;
		}
	}
	if (found)
		tgid = task_tgid_vnr(found);
	rcu_read_unlock();
	return tgid;
}

/*
 * True when the current sender is a thread of system_server. The cached tgid is
 * the fast path; when it stops matching (system_server restarted after the
 * feature was enabled -- it happens across a boot or a zygote restart) fall back
 * to the group leader's name and refresh the cache, so the filter can never go
 * permanently stale. Threads inside system_server have their own comm
 * (SensorService and friends), but the group leader always keeps the process
 * name.
 */
static bool lk1337_gyro_is_server(void)
{
	if (task_tgid_vnr(current) == READ_ONCE(gyro_server_tgid))
		return true;
	if (strcmp(current->group_leader->comm, LK1337_GYRO_SERVER_COMM))
		return false;
	WRITE_ONCE(gyro_server_tgid, task_tgid_vnr(current));
	return true;
}

/*
 * Add two IEEE-754 binary32 bit patterns without using floating point in
 * kernel context.  The reference module uses the same integer mantissa/
 * exponent path: add0/add1 are offsets, not replacement values.  Keeping
 * this as a bit-pattern operation also avoids changing FPSIMD state on the
 * sendto syscall path.
 */
static u32 lk1337_fp32_add(u32 x, u32 y)
{
	u32 sx, sy, ex, ey, mx, my, mant, sign;
	u32 shift;
	u64 wide;

	if ((x & 0x7fffffffU) == 0)
		return y;
	if ((y & 0x7fffffffU) == 0)
		return x;

	sx = x >> 31;
	sy = y >> 31;
	ex = (x >> 23) & 0xffU;
	ey = (y >> 23) & 0xffU;
	mx = x & 0x7fffffU;
	my = y & 0x7fffffU;

	/* Preserve NaN/Inf payloads. */
	if (ex == 0xffU)
		return x;
	if (ey == 0xffU)
		return y;

	/* Use the normal exponent scale for subnormals. */
	if (ex != 0)
		mx |= 0x800000U;
	else
		ex = 1;
	if (ey != 0)
		my |= 0x800000U;
	else
		ey = 1;

	/* Three low bits provide guard/round/sticky room during alignment. */
	mx <<= 3;
	my <<= 3;
	if (ex < ey) {
		shift = ey - ex;
		if (shift > 31)
			shift = 31;
		mx >>= shift;
		ex = ey;
	} else if (ey < ex) {
		shift = ex - ey;
		if (shift > 31)
			shift = 31;
		my >>= shift;
		ey = ex;
	}
	ex = ey = ex;

	if (sx == sy) {
		wide = (u64)mx + my;
		sign = sx;
		if (wide & (1ULL << 27)) {
			wide >>= 1;
			++ex;
		}
		mant = (u32)wide;
	} else if (mx >= my) {
		wide = (u64)mx - my;
		sign = sx;
		mant = (u32)wide;
	} else {
		wide = (u64)my - mx;
		sign = sy;
		mant = (u32)wide;
	}

	if (mant == 0)
		return 0;

	/* Normalize a cancellation result back to the binary32 significand. */
	while (mant < (1U << 26) && ex > 1) {
		mant <<= 1;
		--ex;
	}
	if (mant & (1U << 27)) {
		mant >>= 1;
		++ex;
	}

	/* Round-to-nearest-even using the guard/round/sticky bits. */
	if ((mant & 7U) > 4U || ((mant & 7U) == 4U && (mant & 8U))) {
		mant += 8U;
		if (mant & (1U << 27)) {
			mant >>= 1;
			++ex;
		}
	}

	if (ex >= 0xffU)
		return (sign << 31) | 0x7f800000U;
	if (ex == 1 && mant < (1U << 26))
		return (sign << 31) | (mant >> 3);
	return (sign << 31) | ((ex & 0xffU) << 23) | ((mant >> 3) & 0x7fffffU);
}

static int lk1337_gyro_pre(struct kprobe *kp, struct pt_regs *regs)
{
	/* __arm64_sys_sendto is entered through the syscall wrapper.  On this
	 * kernel the kprobe register frame's X0 points at the syscall argument
	 * frame; the reference 5.10.ko follows X0 then reads +8/+16. */
	struct pt_regs *sysregs = (struct pt_regs *)(uintptr_t)regs->regs[0];
	void __user *ubuf;
	size_t len, i, buffer_size;
	u8 *p;
	u32 type, value0, value1, mask, add0, add1;
	unsigned long flags;

	if (!sysregs)
		return 0;
	ubuf = (void __user *)(uintptr_t)sysregs->regs[1];
	len = (size_t)sysregs->regs[2];

	/* Only system_server's sends are rewritten (SensorService thread). */
	if (!atomic_read(&gyro_enabled))
		return 0;
	smp_rmb();
	if (!lk1337_gyro_is_server())
		return 0;
	if (!ubuf || !len || len > LK1337_GYRO_MAX_PACKET || (len % 0x68) ||
	    !access_ok(ubuf, len))
		return 0;
	p = READ_ONCE(gyro_buffer);
	buffer_size = READ_ONCE(gyro_buffer_size);
	if (!p || len > buffer_size)
		return 0;
	if (!raw_spin_trylock_irqsave(&gyro_buffer_lock, flags))
		return 0;
	/* Kprobe pre-handlers run in atomic context.  The inatomic uaccess
	 * primitives deliberately leave a non-resident/user-invalid buffer alone
	 * instead of faulting or sleeping. */
	if (__copy_from_user_inatomic(p, ubuf, len))
		goto out_unlock;
	mask = READ_ONCE(gyro_mask);
	add0 = READ_ONCE(gyro_add0);
	add1 = READ_ONCE(gyro_add1);
	for (i = 0; i < len; i += 0x68) {
		type = get_unaligned((u32 *)(p + i + 8));
		if ((type == 4 && (mask & 1)) || (type == 16 && (mask & 2))) {
			u32 new0, new1;

			value0 = get_unaligned((u32 *)(p + i + 24));
			value1 = get_unaligned((u32 *)(p + i + 28));
			new0 = lk1337_fp32_add(value0, add0);
			new1 = lk1337_fp32_add(value1, add1);
			put_unaligned(new0, (u32 *)(p + i + 24));
			put_unaligned(new1, (u32 *)(p + i + 28));
			if (atomic_dec_if_positive(&gyro_log_budget) >= 0)
				pr_info("gyro: pid=%d type=%u len=%zu add=(%08x,%08x) x=%08x->%08x y=%08x->%08x\n",
					task_pid_vnr(current), type, len, add0, add1,
					value0, new0, value1, new1);
		}
	}
	if (__copy_to_user_inatomic(ubuf, p, len))
		pr_info_ratelimited("gyro sendto copy_to_user failed (len=%zu)\n", len);
out_unlock:
	raw_spin_unlock_irqrestore(&gyro_buffer_lock, flags);
	return 0;
}
/*
 * The sendto hook runs for every sendto on the system, so it is installed only
 * while the gyro transformer is enabled.  Measured cost of leaving it resident
 * is ~300 ns per sendto (bench/), which is a matched-pair timing differential an
 * unprivileged process can measure.
 */
static struct lk1337_probe lk1337_gyro_probe =
	LK1337_PROBE("__arm64_sys_sendto", "gyro", lk1337_gyro_pre, NULL);
static bool lk1337_gyro_probe_on;

/* Process context only (mutex + text patch). */
static int lk1337_gyro_probe_set(bool on)
{
	int error;

	if (on == lk1337_gyro_probe_on)
		return 0;
	if (on) {
		error = lk1337_probe_use(&lk1337_gyro_probe);
		if (error)
			return error;
	} else {
		lk1337_probe_release(&lk1337_gyro_probe);
	}
	lk1337_gyro_probe_on = on;
	pr_info("gyro: sendto hook %s\n", on ? "installed" : "removed");
	return 0;
}

static int lk1337_gyro_disable(void)
{
	u8 *buffer;
	int error;

	mutex_lock(&gyro_lock);
	atomic_set(&gyro_enabled, 0);
	atomic_set(&gyro_log_budget, 0);
	error = lk1337_gyro_probe_set(false);
	buffer = gyro_buffer;
	WRITE_ONCE(gyro_buffer, NULL);
	WRITE_ONCE(gyro_buffer_size, 0);
	WRITE_ONCE(gyro_server_tgid, 0);
	WRITE_ONCE(gyro_mask, 0);
	WRITE_ONCE(gyro_add0, 0);
	WRITE_ONCE(gyro_add1, 0);
	mutex_unlock(&gyro_lock);
	vfree(buffer);
	return error;
}

static int lk1337_release(struct inode *inode, struct file *file)
{
	struct lk1337_session *session = file->private_data;
	struct lk1337_breakpoint *bp, *next;

	if (!session)
		return 0;
	lk1337_ttbr_session_release(session);
	list_for_each_entry_safe(bp, next, &session->breakpoints, node)
		lk1337_destroy_bp(bp);
	kfree(session->memory_bounce);
	kfree(session);
	return 0;
}

static void lk1337_bootstrap_workfn(struct callback_head *callback)
{
	struct lk1337_bootstrap_work *work = container_of(callback,
							struct lk1337_bootstrap_work, callback);
	struct lk1337_session *session;
	struct file *file;
	int fd;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		goto fail;
	mutex_init(&session->lock);
	INIT_LIST_HEAD(&session->breakpoints);
	INIT_LIST_HEAD(&session->ttbr_views);
	session->next_id = 1;
	session->memory_bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!session->memory_bounce) { kfree(session); goto fail; }
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		kfree(session->memory_bounce);
		kfree(session);
		goto fail;
	}
	file = anon_inode_getfile("[lk1337]", &lk1337_fops, session, O_RDWR);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		kfree(session->memory_bounce);
		kfree(session);
		goto fail;
	}
	if (copy_to_user(&work->request->fd, &fd, sizeof(fd))) {
		pr_warn("bootstrap fd=%d result copy failed\n", fd);
		put_unused_fd(fd);
		fput(file);
		goto out;
	}
	fd_install(fd, file);
	pr_info("bootstrap fd=%d pid=%d\n", fd, task_pid_vnr(current));
	goto out;
fail:
	{
		int error = -ENOMEM;
		(void)copy_to_user(&work->request->fd, &error, sizeof(error));
	}
out:
	kfree(work);
}

static int lk1337_ioctl_hook(struct kprobe *probe, struct pt_regs *regs)
{
	unsigned int cmd = (unsigned int)regs->regs[1];

	if (!lk1337_hook_command(cmd))
		return 0;
	/* memwatch reuses this hook and this workfn: its bootstrap struct is
	 * layout-identical, so the fd lands in the caller's `fd` field either
	 * way. */
	BUILD_BUG_ON(sizeof(struct mw_bootstrap) != sizeof(struct lk1337_bootstrap));
	BUILD_BUG_ON(offsetof(struct mw_bootstrap, fd) !=
		     offsetof(struct lk1337_bootstrap, fd));
	if (!lk1337_root()) {
		regs->regs[0] = -ENOTTY;
		regs->pc = regs->regs[30];
		return 1;
	}
	if (((struct lk1337_bootstrap __user *)regs->regs[2]) == NULL)
		return 0;
	{
		struct lk1337_bootstrap_work *work = kzalloc(sizeof(*work), GFP_ATOMIC);
		if (!work)
			return 0;
		work->request = (void __user *)regs->regs[2];
		work->callback.func = lk1337_bootstrap_workfn;
		if (lk1337_add_task_work(current, &work->callback, TWA_RESUME)) {
			kfree(work);
			return 0;
		}
	}
	/* Keep the original syscall path intact; task-work installs the fd at
	 * TWA_RESUME, just as KernelSU's reboot bootstrap does. */
	return 0;
}

/*
 * The bootstrap hook.  Unlike every other probe in this module it is installed
 * for the whole module lifetime, because it is the only way to hand out a
 * session fd and each new client bootstraps again: a probe that removed itself
 * after the first bootstrap would leave the second client (and every later one)
 * unable to reach the module at all.
 *
 * The cost is bounded and small: the handler compares one register against two
 * constants and returns for every inet_ioctl that is not the bootstrap command,
 * which is a matched-pair differential of about 1.1x on that path (the
 * scheduler and sendto channels, which carried the strong signals, are gone).
 */
static struct lk1337_probe lk1337_ioctl_probe =
	LK1337_PROBE("inet_ioctl", "bootstrap", lk1337_ioctl_hook, NULL);

static int lk1337_resolve_task_work_add(void)
{
	struct kprobe probe = { .symbol_name = "task_work_add" };
	int error = register_kprobe(&probe);

	if (error)
		return error;
	lk1337_task_work_add = (lk1337_task_work_add_t)probe.addr;
	unregister_kprobe(&probe);
	return 0;
}

static int lk1337_legacy_read(struct lk1337_breakpoint *bp, struct lk1337_legacy_hits *request)
{
	struct lk1337_legacy_record *copy;
	const struct lk1337_hit *hit;
	unsigned long flags;
	unsigned int count, index;

	if (request->max_count < 0 || request->max_count > 4096)
		return -EINVAL;
	count = min_t(unsigned int, request->max_count, bp->capacity);
	copy = kvcalloc(count, sizeof(*copy), GFP_KERNEL);
	if (count && !copy)
		return -ENOMEM;
	raw_spin_lock_irqsave(&bp->lock, flags);
	count = min(count, bp->count);
	for (index = 0; index < count; index++) {
		hit = &bp->ring[(bp->head + index) % bp->capacity];
		copy[index].addr = hit->addr;
		copy[index].pid = hit->pid;
		copy[index].tid = hit->tid;
		memcpy(&copy[index].snap.regs.user_regs, &hit->before,
		       sizeof(struct user_pt_regs));
		memcpy(copy[index].snap.vregs, hit->before.vregs,
		       sizeof(hit->before.vregs));
		copy[index].snap.fpsr = hit->before.fpsr;
		copy[index].snap.fpcr = hit->before.fpcr;
		copy[index].snap.pc = hit->before.pc;
		copy[index].snap.pstate = hit->before.pstate;
		copy[index].snap.timestamp = hit->timestamp;
		copy[index].hit_count = hit->sequence;
	}
	raw_spin_unlock_irqrestore(&bp->lock, flags);
	request->actual_count = count;
	if (count && copy_to_user(u64_to_user_ptr(request->buffer), copy,
				  count * sizeof(*copy))) {
		kvfree(copy);
		return -EFAULT;
	}
	kvfree(copy);
	return 0;
}

static long lk1337_dispatch(struct lk1337_session *session, unsigned int cmd,
				void __user *arg)
{
	union {
		struct lk1337_memory memory;
		struct lk1337_base base;
		struct lk1337_create create;
		struct lk1337_id id;
		struct lk1337_template change;
		struct lk1337_hits hits;
		struct lk1337_legacy_hits legacy_hits;
		struct lk1337_legacy_modify modify;
		struct lk1337_gyro_config gyro;
		struct lk1337_maps_filter maps;
		struct lk1337_maps_filter_pid maps_pid;
	} request;
	struct lk1337_breakpoint *bp;
	unsigned long flags;
	int error, id;
	size_t size;
	/* memwatch commands are module-level state, not per-session. */
	if (lk1337_memwatch_command(cmd))
		return lk1337_memwatch_dispatch(cmd, arg);
	error = lk1337_ttbr_dispatch(session, cmd, arg);
	if (error != -ENOTTY)
		return error;
	if (cmd == LK1337_GYRO_CONFIG) {
		if (copy_from_user(&request.gyro, arg, sizeof(request.gyro)))
			return -EFAULT;
		if (request.gyro.enable) {
			pid_t tgid = lk1337_gyro_find_server();
			u8 *buffer;

			if (!tgid) {
				pr_warn("gyro: system_server not found, not enabling\n");
				return -ESRCH;
			}
			mutex_lock(&gyro_lock);
			if (!gyro_buffer) {
				buffer = vmalloc(LK1337_GYRO_MAX_PACKET);
				if (!buffer) {
					mutex_unlock(&gyro_lock);
					return -ENOMEM;
				}
				WRITE_ONCE(gyro_buffer, buffer);
				WRITE_ONCE(gyro_buffer_size, LK1337_GYRO_MAX_PACKET);
			}
			WRITE_ONCE(gyro_server_tgid, tgid);
			WRITE_ONCE(gyro_mask, request.gyro.type_mask);
			WRITE_ONCE(gyro_add0, request.gyro.add0);
			WRITE_ONCE(gyro_add1, request.gyro.add1);
			/* Only while the transformer is on does anything need the hook;
			 * keep the enabled gate closed until registration succeeds. */
			error = lk1337_gyro_probe_set(true);
			if (error) {
				buffer = gyro_buffer;
				WRITE_ONCE(gyro_buffer, NULL);
				WRITE_ONCE(gyro_buffer_size, 0);
				WRITE_ONCE(gyro_server_tgid, 0);
				WRITE_ONCE(gyro_mask, 0);
				WRITE_ONCE(gyro_add0, 0);
				WRITE_ONCE(gyro_add1, 0);
				mutex_unlock(&gyro_lock);
				vfree(buffer);
				return error;
			}
			smp_wmb();
			atomic_set(&gyro_enabled, 1);
			atomic_set(&gyro_log_budget, LK1337_GYRO_LOG_SAMPLES);
			mutex_unlock(&gyro_lock);
		} else {
			error = lk1337_gyro_disable();
			if (error)
				return error;
		}
		pr_info("gyro: %s mask=0x%x add0=0x%08x add1=0x%08x tgid=%d\n",
			request.gyro.enable ? "enabled" : "disabled",
			request.gyro.type_mask, request.gyro.add0,
			request.gyro.add1,
			request.gyro.enable ? gyro_server_tgid : 0);
		return 0;
	}
	/* Maps filter commands */
	if (cmd == LK1337_MAPS_FILTER_ADD) {
		if (copy_from_user(&request.maps, arg, sizeof(request.maps)))
			return -EFAULT;
		request.maps.pattern[sizeof(request.maps.pattern) - 1] = '\0';
		return lk1337_add_hide_pattern(request.maps.pattern);
	}
	if (cmd == LK1337_MAPS_FILTER_REMOVE) {
		if (copy_from_user(&request.maps, arg, sizeof(request.maps)))
			return -EFAULT;
		request.maps.pattern[sizeof(request.maps.pattern) - 1] = '\0';
		return lk1337_remove_hide_pattern(request.maps.pattern);
	}
	if (cmd == LK1337_MAPS_FILTER_CLEAR) {
		lk1337_clear_hide_patterns();
		return 0;
	}
	if (cmd == LK1337_MAPS_FILTER_ENABLE) {
		if (copy_from_user(&request.maps, arg, sizeof(request.maps)))
			return -EFAULT;
		if (!request.maps.enable) {
			lk1337_maps_filter_disable();
			return 0;
		}
		lk1337_set_filter_all(true);
		return lk1337_maps_filter_init();
	}
	/* Maps filter PID commands */
	if (cmd == LK1337_MAPS_FILTER_ADD_PID) {
		if (copy_from_user(&request.maps_pid, arg, sizeof(request.maps_pid)))
			return -EFAULT;
		return lk1337_add_filter_pid(request.maps_pid.pid);
	}
	if (cmd == LK1337_MAPS_FILTER_REMOVE_PID) {
		if (copy_from_user(&request.maps_pid, arg, sizeof(request.maps_pid)))
			return -EFAULT;
		return lk1337_remove_filter_pid(request.maps_pid.pid);
	}
	if (cmd == LK1337_MAPS_FILTER_CLEAR_PID) {
		lk1337_clear_filter_pids();
		return 0;
	}
	if (cmd == LK1337_MAPS_FILTER_SET_ALL) {
		if (copy_from_user(&request.maps_pid, arg, sizeof(request.maps_pid)))
			return -EFAULT;
		lk1337_set_filter_all(request.maps_pid.enable != 0);
		/* SET_ALL is a complete mode switch: callers should not need a
		 * separate ENABLE ioctl for the hooks to become active. */
		if (request.maps_pid.enable)
			return lk1337_maps_filter_init();
		return 0;
	}
	switch (cmd) {
	case LK1337_READ:
	case LK1337_WRITE: size = sizeof(request.memory); break;
	case LK1337_BASE: size = sizeof(request.base); break;
	case LK1337_BP_CREATE: size = sizeof(request.create); break;
	case LK1337_BP_REMOVE:
	case LK1337_BP_CLEAR: size = sizeof(request.id); break;
	case LK1337_BP_TEMPLATE: size = sizeof(request.change); break;
	case LK1337_BP_HITS: size = sizeof(request.hits); break;
	case LK1337_BP_PAUSE:
	case LK1337_BP_RESUME: size = sizeof(request.id); break;
	case LK1337_BP_LEGACY_HITS: size = sizeof(request.legacy_hits); break;
	case LK1337_BP_LEGACY_MODIFY: size = sizeof(request.modify); break;
	default: return -ENOTTY;
	}
	if (copy_from_user(&request, arg, size))
		return -EFAULT;
	if (cmd == LK1337_READ || cmd == LK1337_WRITE)
		return lk1337_memory_transfer(&request.memory, cmd == LK1337_WRITE,
					      session->memory_bounce);
	if (cmd == LK1337_BASE) {
		error = lk1337_module_base(&request.base);
		if (!error && copy_to_user(arg, &request.base, size))
			error = -EFAULT;
		return error;
	}
	if (cmd == LK1337_BP_CREATE) {
		error = lk1337_create_bp(session, &request.create);
		if (!error && copy_to_user(arg, &request.create, size)) {
			bp = lk1337_find(session, request.create.bp_id);
			lk1337_destroy_bp(bp);
			return -EFAULT;
		}
		return error;
	}
	id = request.id.bp_id;
	bp = lk1337_find(session, id);
	if (!bp)
		return -ENOENT;
	switch (cmd) {
	case LK1337_BP_REMOVE:
		lk1337_destroy_bp(bp);
		return 0;
	case LK1337_BP_PAUSE:
		return lk1337_bp_pause(bp);
	case LK1337_BP_RESUME:
		return lk1337_bp_resume(bp);
	case LK1337_BP_CLEAR:
		raw_spin_lock_irqsave(&bp->lock, flags);
		bp->head = 0;
		bp->count = 0;
		bp->total = 0;
		bp->dropped = 0;
		bp->fp_unavailable = 0;
		raw_spin_unlock_irqrestore(&bp->lock, flags);
		return 0;
	case LK1337_BP_TEMPLATE:
		return lk1337_set_template(bp, &request.change);
	case LK1337_BP_HITS:
		error = lk1337_read_hits(bp, &request.hits);
		if (!error && copy_to_user(arg, &request.hits, size))
			error = -EFAULT;
		return error;
	case LK1337_BP_LEGACY_HITS:
		error = lk1337_legacy_read(bp, &request.legacy_hits);
		if (!error && copy_to_user(arg, &request.legacy_hits, size))
			error = -EFAULT;
		return error;
	case LK1337_BP_LEGACY_MODIFY: {
		struct lk1337_template change;
		int index = request.modify.reg_index;
		u64 value = request.modify.value;

		if (request.modify.record_index != -1)
			return -EOPNOTSUPP;
		if (index < 0 || index > 33)
			return -EINVAL;
		raw_spin_lock_irqsave(&bp->lock, flags);
		change = bp->change;
		raw_spin_unlock_irqrestore(&bp->lock, flags);
		change.flags = LK1337_ONESHOT;
		change.gp_mask |= BIT_ULL(index);
		if (index < 31)
			change.values.regs[index] = value;
		else if (index == 31)
			change.values.sp = value;
		else if (index == 32)
			change.values.pc = value;
		else
			change.values.pstate = value;
		return lk1337_set_template(bp, &change);
	}
	default:
		return -ENOTTY;
	}
}

static long lk1337_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct lk1337_session *session = file->private_data;
	long result;

	if (!lk1337_root())
		return -ENOTTY;
	if (!session)
		return -EIO;
	mutex_lock(&session->lock);
	result = lk1337_dispatch(session, cmd, (void __user *)arg);
	mutex_unlock(&session->lock);
	pr_info_ratelimited("ioctl pid=%d cmd=%u result=%ld\n",
			    task_pid_vnr(current), cmd, result);
	return result;
}

static const struct file_operations lk1337_fops = {
	.owner = THIS_MODULE,
	.release = lk1337_release,
	.unlocked_ioctl = lk1337_ioctl,
	.llseek = NULL,
};

static int __init lk1337_init(void)
{
	int error;

	/*
	 * The probe manager resolves enable_kprobe()/disable_kprobe(), which the
	 * features use to install and remove their hooks on demand.  A module
	 * that is loaded but idle must have no probe in the kernel at all: that
	 * is what makes it invisible to a matched-pair syscall timing probe.
	 */
	error = lk1337_probe_manager_init();
	if (error) {
		pr_err("probe manager unavailable: %d\n", error);
		return error;
	}
	/* Nothing below registers a kprobe up front any more.  Only the
	 * bootstrap probe is needed to hand out the first session fd, and it
	 * removes itself as soon as it has done so. */
	error = lk1337_probe_use(&lk1337_ioctl_probe);
	if (error) {
		pr_err("bootstrap hook unavailable: %d\n", error);
		return error;
	}
	error = lk1337_ttbr_init();
	if (error) {
		lk1337_probe_release(&lk1337_ioctl_probe);
		pr_err("TTBR initialization failed: %d\n", error);
		return error;
	}
	error = lk1337_resolve_task_work_add();
	if (error) {
		lk1337_ttbr_exit();
		lk1337_probe_release(&lk1337_ioctl_probe);
		return error;
	}
	/* Process hiding is optional: a kernel without the procfs hooks still
	 * gets the memory/breakpoint core. */
	error = lk1337_memwatch_init();
	if (error)
		pr_warn("process hiding unavailable (%d), continuing without it\n",
			error);
	/* Page-table (UXN) execution breakpoints are optional too: without the
	 * fault_info/step-hook symbols the perf backend still works. */
	error = lk1337_uxn_init(lk1337_task_work_add);
	if (error)
		pr_warn("UXN execution breakpoints unavailable (%d), continuing without them\n",
			error);
	pr_info("loaded ABI=%d anonymous-fd bootstrap\n", LK1337_ABI_VERSION);
	return 0;
}

static void __exit lk1337_exit(void)
{
	lk1337_gyro_disable();
	lk1337_uxn_exit();
	lk1337_memwatch_exit();
	lk1337_ttbr_exit();
	lk1337_maps_filter_exit();
	lk1337_probe_release(&lk1337_ioctl_probe);
	pr_info("unloaded\n");
}

module_init(lk1337_init);
module_exit(lk1337_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ARM64 process memory and hardware breakpoint debugger");
