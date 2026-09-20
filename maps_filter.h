#ifndef LK1337_MAPS_FILTER_H
#define LK1337_MAPS_FILTER_H

#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include "internal.h" /* get_proc_task()/PROC_I for proc map_files inodes */

/*
 * CFI builds rename internal-linkage functions whose address is taken to
 * "name$<hash>". The hash is per compilation unit, not per function type:
 * every address-taken static of one LTO unit shares it (verified -- in this
 * module entry.o uses $4e8b0154… for both a kprobe pre_handler and the sendmsg
 * callback, memwatch.o uses $cf7a1e40…; in the kernel fs/proc/task_mmu.c uses
 * $f0f99e7d… and fs/proc/base.c uses $181a70ca…). On the target 5.10.226 GKI
 * image show_map_vma, show_smap, show_smaps_rollup, proc_map_files_* and
 * proc_pid_readlink therefore have no plain name at all. kprobe's symbol_name
 * lookup is exact, so those probes silently fail to register; resolve the
 * suffixed name through kallsyms and attach by address instead.
 *
 * kallsyms_on_each_symbol is not exported, but any function's address can be
 * obtained by registering a throwaway kprobe on it and reading probe.addr --
 * the same technique ttbr_view.c uses for kallsyms_lookup_name.
 */
typedef int (*lk1337_kallsyms_cb_t)(void *data, const char *name,
				    struct module *mod, unsigned long addr);
typedef int (*lk1337_on_each_symbol_t)(lk1337_kallsyms_cb_t cb, void *data);

static lk1337_on_each_symbol_t lk1337_on_each_symbol;

static void *lk1337_resolve_func(const char *name)
{
	struct kprobe probe = { .symbol_name = name };
	void *addr;

	if (register_kprobe(&probe))
		return NULL;
	addr = probe.addr;
	unregister_kprobe(&probe);
	return addr;
}

struct lk1337_symbol_lookup {
	const char *name;
	unsigned long addr;
};

static int lk1337_symbol_cb(void *data, const char *name, struct module *mod,
			    unsigned long addr)
{
	struct lk1337_symbol_lookup *lookup = data;
	size_t len = strlen(lookup->name);
	const char *suffix;

	/* Core kernel only: module symbols never carry the CFI suffix. */
	if (mod)
		return 0;
	if (strncmp(name, lookup->name, len))
		return 0;
	if (name[len] == '\0') {
		lookup->addr = addr;
		return 1;
	}
	if (name[len] != '$')
		return 0;
	/* "name$<hex hash>" is the function; "name$<hash>.cfi_jt" and
	 * "name$hash.cold" are different entry points, so require hex only. */
	for (suffix = name + len + 1; *suffix; suffix++) {
		if (!isxdigit((unsigned char)*suffix))
			return 0;
	}
	if (suffix == name + len + 1)
		return 0;
	lookup->addr = addr;
	return 1;
}

static unsigned long lk1337_lookup_symbol(const char *name)
{
	struct lk1337_symbol_lookup lookup = { .name = name, .addr = 0 };

	if (!lk1337_on_each_symbol)
		return 0;
	lk1337_on_each_symbol(lk1337_symbol_cb, &lookup);
	return lookup.addr;
}

/*
 * Register a kprobe on a kernel symbol, tolerating both plain and CFI-renamed
 * (name$hash) spellings. Returns the register_kprobe() error when neither
 * resolves. kprobe requires exactly one of symbol_name/addr to be set.
 */
static int lk1337_register_kprobe(struct kprobe *kp, const char *name)
{
	unsigned long addr;
	int error;

	kp->symbol_name = name;
	kp->addr = NULL;
	error = register_kprobe(kp);
	if (!error || !lk1337_on_each_symbol)
		return error;

	addr = lk1337_lookup_symbol(name);
	if (!addr)
		return error;
	kp->symbol_name = NULL;
	kp->addr = (kprobe_opcode_t *)addr;
	error = register_kprobe(kp);
	if (!error)
		pr_info("resolved %s via CFI-renamed symbol at %px\n", name,
			(void *)addr);
	return error;
}

static void lk1337_str_tolower(char *s)
{
	for (; *s; s++) {
		if (*s >= 'A' && *s <= 'Z')
			*s = *s - 'A' + 'a';
	}
}

/* 要隐藏的模块路径关键字列表 */
static const char *lk1337_hide_patterns[] = {
	"frida",
	"xposed",
	"lsposed",
	"edxposed",
	"substrate",
	"libxhook",
	"libdobby",
	"libinlinehook",
	"magisk",
	"riru",
	"zygisk",
	"libriru",
	"libmemtrack_real",
	"/data/local/tmp/",  /* 临时目录的so */
	"re.frida.server",
	"gadget",
	NULL
};

/* 用户态配置：动态添加/删除隐藏规则 */
#define MAX_CUSTOM_PATTERNS 32
static char *lk1337_custom_patterns[MAX_CUSTOM_PATTERNS];
static int lk1337_custom_pattern_count = 0;
/* Raw spinlock, see lk1337_pid_lock. */
static DEFINE_RAW_SPINLOCK(lk1337_pattern_lock);

/* Per-PID过滤配置 */
#define MAX_FILTER_PIDS 16
static pid_t lk1337_filter_pids[MAX_FILTER_PIDS];
static int lk1337_filter_pid_count = 0;
/* Global filtering is the default once maps hooks are enabled. */
static bool lk1337_filter_all_pids = true;  /* true=全局过滤，false=仅过滤指定PID */
static bool lk1337_maps_filter_enabled;
/* Raw spinlock: readers run inside kprobe pre_handlers, which may fire with
 * preemption or interrupts disabled (memwatch uses the same rule). */
static DEFINE_RAW_SPINLOCK(lk1337_pid_lock);

/*
 * Per-PID selection is about the process whose maps are being printed, not the
 * reader: `cat /proc/1234/maps` must consult pid 1234. The probe handlers take
 * that task from m->private (struct proc_maps_private in fs/proc/internal.h).
 */
static bool lk1337_should_filter_task(struct task_struct *task)
{
	unsigned long flags;
	pid_t pid;
	bool found = false;
	int i;

	/* 全局过滤模式 */
	if (READ_ONCE(lk1337_filter_all_pids))
		return true;
	if (!task)
		return false;

	pid = task_pid_vnr(task);
	raw_spin_lock_irqsave(&lk1337_pid_lock, flags);
	for (i = 0; i < lk1337_filter_pid_count; i++) {
		if (lk1337_filter_pids[i] == pid) {
			found = true;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&lk1337_pid_lock, flags);
	return found;
}

/*
 * Target task of the /proc/<pid>/maps style seq_file being printed. Only
 * task_mmu.c's maps/smaps seq_operations pass a proc_maps_private here.
 */
static struct task_struct *lk1337_maps_target(struct seq_file *m)
{
	struct proc_maps_private *priv = m ? m->private : NULL;

	return priv ? priv->task : NULL;
}

/*
 * Gate for the maps/smaps line hooks. Global mode (the default) answers without
 * touching m->private at all, which keeps the common case independent of the
 * vendor's struct proc_maps_private layout; only per-PID mode reads the target
 * task out of it.
 */
static bool lk1337_should_filter_maps(struct seq_file *m)
{
	if (READ_ONCE(lk1337_filter_all_pids))
		return true;
	return lk1337_should_filter_task(lk1337_maps_target(m));
}

/*
 * Shared d_path() scratch buffer. This used to be a per-VMA
 * kmalloc(PATH_MAX, GFP_ATOMIC), i.e. one 4 KB allocation per mapping per
 * read; the buffer is serialized now. Lock order is path_lock -> pattern_lock
 * and never the reverse.
 */
static char lk1337_path_buf[PATH_MAX];
static DEFINE_RAW_SPINLOCK(lk1337_path_lock);

/* 检查VMA路径是否需要隐藏 */
static bool lk1337_should_hide_vma(struct vm_area_struct *vma)
{
	struct file *file;
	const char *name;
	char *pathname;
	unsigned long flags;
	bool hide = false;
	int i;

	if (!vma)
		return false;

	file = vma->vm_file;
	if (!file)
		return false;  /* 匿名映射不隐藏 */

	raw_spin_lock_irqsave(&lk1337_path_lock, flags);

	pathname = d_path(&file->f_path, lk1337_path_buf, PATH_MAX);
	if (IS_ERR(pathname)) {
		/*
		 * d_path failed: copy the dentry name into our own buffer
		 * instead. Never case-fold in place -- d_name.name is shared,
		 * const VFS-owned memory, and writing to it corrupts the dentry.
		 */
		name = file->f_path.dentry ?
			(const char *)file->f_path.dentry->d_name.name : NULL;
		if (!name || strscpy(lk1337_path_buf, name, PATH_MAX) < 0)
			goto out;
		pathname = lk1337_path_buf;
	}

	/* 转小写比较，避免大小写绕过 */
	lk1337_str_tolower(pathname);

	/* 检查内置规则 */
	for (i = 0; lk1337_hide_patterns[i]; i++) {
		if (strstr(pathname, lk1337_hide_patterns[i])) {
			hide = true;
			pr_info_ratelimited("hiding VMA (builtin %s)\n",
					    lk1337_hide_patterns[i]);
			goto out;
		}
	}

	/* 检查用户自定义规则（入库时已转小写） */
	raw_spin_lock(&lk1337_pattern_lock);
	for (i = 0; i < lk1337_custom_pattern_count; i++) {
		if (lk1337_custom_patterns[i] &&
		    strstr(pathname, lk1337_custom_patterns[i])) {
			hide = true;
			pr_info_ratelimited("hiding VMA (custom %s)\n",
					    lk1337_custom_patterns[i]);
			break;
		}
	}
	raw_spin_unlock(&lk1337_pattern_lock);

out:
	raw_spin_unlock_irqrestore(&lk1337_path_lock, flags);
	return hide;
}

/*
 * Hook show_map_vma() 函数
 * 用于过滤 /proc/pid/maps
 */
static int lk1337_show_map_vma_pre(struct kprobe *p, struct pt_regs *regs)
{
	/* ARM64: x0 = seq_file*, x1 = vma* */
	struct seq_file *m = (struct seq_file *)regs->regs[0];
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];

	/* 先检查是否应该过滤这个目标进程（不是读者） */
	if (!lk1337_should_filter_maps(m))
		return 0;  /* 不过滤，继续执行原函数 */

	if (lk1337_should_hide_vma(vma)) {
		/*
		 * show_map_vma() is void and called from show_map(), so jumping to
		 * LR drops this VMA's line and lets show_map() return 0 while the
		 * iterator moves on. A non-zero kprobe return alone only
		 * suppresses the probe's single-step, hence the explicit pc.
		 */
		regs->pc = regs->regs[30];
		return 1;
	}

	return 0;  /* 继续执行原函数 */
}

static struct kprobe lk1337_show_map_kp = {
	.symbol_name = "show_map_vma",
	.pre_handler = lk1337_show_map_vma_pre,
};

/*
 * Hook show_smap() 函数
 * 用于过滤 /proc/pid/smaps
 *
 * show_smap() 先调用show_map_vma()输出基本信息，
 * 然后输出Size/Rss/Pss等详细统计
 */
static int lk1337_show_smap_pre(struct kprobe *p, struct pt_regs *regs)
{
	/* ARM64: x0 = seq_file*, x1 = vma* (void *v) */
	struct seq_file *m = (struct seq_file *)regs->regs[0];
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];

	/* 先检查是否应该过滤这个目标进程（不是读者） */
	if (!lk1337_should_filter_maps(m))
		return 0;

	if (lk1337_should_hide_vma(vma)) {
		/*
		 * show_smap() returns int and *is* the seq_operations .show
		 * callback, so its caller (seq_read_iter) consumes the return
		 * value. Jumping to LR used to leave x0 holding the incoming
		 * seq_file pointer, whose sign decided between "discard" and a
		 * hard read error. Return SEQ_SKIP explicitly.
		 */
		regs->regs[0] = SEQ_SKIP;
		regs->pc = regs->regs[30];
		return 1;
	}

	return 0;
}

static struct kprobe lk1337_show_smap_kp = {
	.symbol_name = "show_smap",
	.pre_handler = lk1337_show_smap_pre,
};

/*
 * /proc/<pid>/smaps_rollup 是单条汇总记录，没有按 VMA 抑制的机会：本内核把
 * smap_gather_stats() 内联掉了（kallsyms 里不存在，无法 hook），而汇总也无法在
 * 排除隐藏 VMA 后重算。唯一诚实的做法是抑制整条记录，否则汇总数字会与已过滤的
 * /proc/<pid>/smaps 不一致，直接暴露隐藏映射；mm 中没有需要隐藏的 VMA 的进程
 * 完全不受影响。
 */
static bool lk1337_mm_has_hidden_vma(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	bool found = false;

	/* Caller holds an mm reference. */
	if (!mm)
		return false;
	mmap_read_lock(mm);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (lk1337_should_hide_vma(vma)) {
			found = true;
			break;
		}
	}
	mmap_read_unlock(mm);
	return found;
}

static int lk1337_show_smaps_rollup_pre(struct kprobe *p, struct pt_regs *regs)
{
	/* x0 = seq_file*, x1 = void *v (single_open passes 1, not a vma) */
	struct seq_file *m = (struct seq_file *)regs->regs[0];
	struct proc_maps_private *priv = m ? m->private : NULL;
	struct task_struct *task;
	struct mm_struct *mm;
	bool hide;

	/*
	 * smaps_rollup_open() uses single_open(), so priv->task is not
	 * populated yet but priv->inode is. Only that leading field is read;
	 * the mm comes from the kernel's own accessor rather than from a
	 * guessed offset in proc_maps_private.
	 */
	if (!priv || !priv->inode)
		return 0;
	task = get_proc_task(priv->inode);
	if (!task)
		return 0;
	if (!lk1337_should_filter_task(task)) {
		put_task_struct(task);
		return 0;
	}
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return 0;
	hide = lk1337_mm_has_hidden_vma(mm);
	mmput(mm);
	if (!hide)
		return 0;

	regs->regs[0] = 0;  /* int return: empty record, so the file reads empty */
	regs->pc = regs->regs[30];
	return 1;
}

static struct kprobe lk1337_show_smaps_rollup_kp = {
	.symbol_name = "show_smaps_rollup",
	.pre_handler = lk1337_show_smaps_rollup_pre,
};

/*
 * There is deliberately no show_vma_header_prefix() fallback any more. Its real
 * signature is (m, start, end, flags, pgoff, dev, ino) -- no VMA argument -- so
 * the old handler dereferenced a virtual address as a struct vm_area_struct,
 * i.e. it would oops as soon as it registered. Skipping only the header could
 * not suppress the mapping path printed right afterwards either. show_map_vma()
 * is now resolved through the CFI name lookup above; if that ever fails, maps
 * filtering is reported as unavailable instead of half-working.
 */

static bool lk1337_map_files_selected(struct task_struct *task)
{
	return lk1337_should_filter_task(task);
}

static bool lk1337_map_files_range(struct dentry *dentry,
					unsigned long *start, unsigned long *end)
{
	char *dash, *stop;
	if (!dentry)
		return false;
	dash = strchr(dentry->d_name.name, '-');
	if (!dash)
		return false;
	*start = simple_strtoul(dentry->d_name.name, &stop, 16);
	if (stop != dash)
		return false;
	*end = simple_strtoul(dash + 1, &stop, 16);
	return stop != dash + 1 && *stop == '\0';
}

static bool lk1337_map_files_should_hide(struct task_struct *task,
						struct dentry *dentry)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long start, end;
	bool hide = false;
	if (!lk1337_map_files_selected(task) ||
	    !lk1337_map_files_range(dentry, &start, &end))
		return false;
	mm = get_task_mm(task);
	if (!mm)
		return false;
	mmap_read_lock(mm);
	vma = find_vma(mm, start);
	if (vma && vma->vm_start == start && vma->vm_end == end)
		hide = lk1337_should_hide_vma(vma);
	mmap_read_unlock(mm);
	mmput(mm);
	return hide;
}

/* Hide map_files symlink resolution for filtered VMAs. The proc inode carries
 * the target pid; the dentry name encodes the VMA range (start-end). */
static int lk1337_map_files_link_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[0];
	struct inode *inode;
	struct task_struct *task;
	if (!dentry) return 0;
	inode = d_inode(dentry);
	if (!inode) return 0;
	task = get_proc_task(inode);
	if (!task) return 0;
	if (lk1337_map_files_should_hide(task, dentry)) {
		pr_info_ratelimited("map_files filtered target=%d range=%lx-%lx\n",
				   task_pid_vnr(task), 0UL, 0UL);
		put_task_struct(task);
		regs->regs[0] = (unsigned long)-ENOENT;
		regs->pc = regs->regs[30];
		return 1;
	}
	put_task_struct(task);
	return 0;
}

static struct kprobe lk1337_map_files_link_kp = {
	.symbol_name = "proc_map_files_get_link",
	.pre_handler = lk1337_map_files_link_pre,
};

/* Target-task aware filter at the point proc creates a map_files symlink.
 * proc_map_files_instantiate(dentry, task, mode) supplies the target task
 * directly, unlike readlink helpers whose current task is only the reader. */
static int lk1337_map_files_instantiate_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[0];
	struct task_struct *task;
	if (!dentry) return 0;
	task = (struct task_struct *)regs->regs[1];
	if (!task) return 0;
	if (lk1337_map_files_should_hide(task, dentry)) {
		pr_info_ratelimited("map_files instantiate filtered target=%d\n",
				   task_pid_vnr(task));
		regs->regs[0] = (unsigned long)ERR_PTR(-ENOENT);
		regs->pc = regs->regs[30];
		return 1;
	}
	return 0;
}

static struct kprobe lk1337_map_files_instantiate_kp = {
	.symbol_name = "proc_map_files_instantiate",
	.pre_handler = lk1337_map_files_instantiate_pre,
};

static int lk1337_map_files_lookup_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *dir = (struct inode *)regs->regs[0];
	struct dentry *dentry = (struct dentry *)regs->regs[1];
	struct task_struct *task;
	if (!dir || !dentry)
		return 0;
	task = get_proc_task(dir);
	if (!task)
		return 0;
	if (lk1337_map_files_should_hide(task, dentry)) {
		pr_info_ratelimited("map_files lookup filtered target=%d\n", task_pid_vnr(task));
		put_task_struct(task);
		regs->regs[0] = (unsigned long)ERR_PTR(-ENOENT);
		regs->pc = regs->regs[30];
		return 1;
	}
	put_task_struct(task);
	return 0;
}

static struct kprobe lk1337_map_files_lookup_kp = {
	.symbol_name = "proc_map_files_lookup",
	.pre_handler = lk1337_map_files_lookup_pre,
};

/* proc_fill_cache is where map_files directory entries are emitted. Returning
 * true without calling it suppresses one name while allowing readdir to
 * continue with subsequent mappings. */
static int lk1337_map_files_fill_cache_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs->regs[0];
	struct dentry *dentry;
	struct dentry name_dentry;
	struct task_struct *task = (struct task_struct *)regs->regs[5];
	const char *name = (const char *)regs->regs[2];
	if (!file || !task || !name || !file->f_path.dentry)
		return 0;
	dentry = file->f_path.dentry;
	if (strcmp(dentry->d_name.name, "map_files"))
		return 0;
	memset(&name_dentry, 0, sizeof(name_dentry));
	name_dentry.d_name.name = name;
	if (lk1337_map_files_should_hide(task, &name_dentry)) {
		pr_info_ratelimited("map_files readdir filtered target=%d name=%s\n",
				   task_pid_vnr(task), name);
		regs->regs[0] = 1;
		regs->pc = regs->regs[30];
		return 1;
	}
	return 0;
}

static struct kprobe lk1337_map_files_fill_cache_kp = {
	.symbol_name = "proc_fill_cache",
	.pre_handler = lk1337_map_files_fill_cache_pre,
};

/* `ls -l` uses the readlink operation directly and therefore bypasses
 * proc_map_files_get_link. Deny readlink on map_files entries while filtering
 * is active; directory names remain enumerable, but their targets are not
 * exposed to callers. */
static int __maybe_unused lk1337_map_files_readlink_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[0];
	struct inode *inode;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long start, end;
	char *dash, *stop;
	pid_t target_pid;
	if (!dentry || !dentry->d_parent ||
	    strcmp(dentry->d_parent->d_name.name, "map_files"))
		return 0;
	inode = d_inode(dentry);
	if (!inode) return 0;
	task = get_proc_task(inode);
	if (!task) return 0;
	if (!lk1337_should_filter_task(task)) { put_task_struct(task); return 0; }
	dash = strchr(dentry->d_name.name, '-');
	if (!dash) { put_task_struct(task); return 0; }
	start = simple_strtoul(dentry->d_name.name, &stop, 16);
	if (stop != dash) { put_task_struct(task); return 0; }
	end = simple_strtoul(dash + 1, &stop, 16);
	if (stop == dash + 1 || *stop) { put_task_struct(task); return 0; }
	/* Read the pid before dropping the task reference: task_pid_vnr() on a
	 * task that was already put is a use-after-free. */
	target_pid = task_pid_vnr(task);
	mm = get_task_mm(task); put_task_struct(task);
	if (!mm) return 0;
	mmap_read_lock(mm); vma = find_vma(mm, start);
	if (vma && vma->vm_start == start && vma->vm_end == end && lk1337_should_hide_vma(vma)) {
		mmap_read_unlock(mm); mmput(mm);
		pr_info_ratelimited("map_files readlink filtered target=%d range=%lx-%lx\n",
				   target_pid, start, end);
		regs->regs[0] = (unsigned long)-ENOENT;
		regs->pc = regs->regs[30];
		return 1;
	}
	mmap_read_unlock(mm); mmput(mm);
	return 0;
}

static struct kprobe lk1337_map_files_readlink_kp = {
	.symbol_name = "proc_pid_readlink",
	.pre_handler = lk1337_map_files_readlink_pre,
};

/* 初始化maps过滤 */
static int lk1337_maps_filter_init(void)
{
	int error;
	int hooks_registered = 0;
	if (lk1337_maps_filter_enabled)
		return 0;

	/*
	 * Resolve kallsyms_on_each_symbol first: on CFI builds the static proc
	 * functions are renamed to "name$<typehash>" and can only be found
	 * through kallsyms. Without it only the plain spellings are tried.
	 */
	if (!lk1337_on_each_symbol) {
		lk1337_on_each_symbol = (lk1337_on_each_symbol_t)
			lk1337_resolve_func("kallsyms_on_each_symbol");
		if (!lk1337_on_each_symbol)
			pr_warn("kallsyms_on_each_symbol unavailable, CFI-renamed hooks cannot be resolved\n");
	}

	/* Hook 1: show_map_vma - 用于/proc/pid/maps */
	error = lk1337_register_kprobe(&lk1337_show_map_kp, "show_map_vma");
	if (error) {
		pr_warn("failed to hook show_map_vma (%d), /proc/pid/maps NOT filtered\n",
			error);
	} else {
		pr_info("maps filter: hooked show_map_vma for /proc/pid/maps\n");
		hooks_registered++;
	}

	/* Hook 2: show_smap - 用于/proc/pid/smaps */
	error = lk1337_register_kprobe(&lk1337_show_smap_kp, "show_smap");
	if (error) {
		pr_warn("failed to hook show_smap (%d), /proc/pid/smaps NOT filtered\n", error);
	} else {
		pr_info("maps filter: hooked show_smap for /proc/pid/smaps\n");
		hooks_registered++;
	}

	/* Hook 3: show_smaps_rollup - 用于/proc/pid/smaps_rollup */
	error = lk1337_register_kprobe(&lk1337_show_smaps_rollup_kp, "show_smaps_rollup");
	if (error) {
		pr_warn("failed to hook show_smaps_rollup (%d), /proc/pid/smaps_rollup NOT filtered\n", error);
	} else {
		pr_info("maps filter: hooked show_smaps_rollup for /proc/pid/smaps_rollup\n");
		hooks_registered++;
	}
	if (!lk1337_register_kprobe(&lk1337_map_files_link_kp, "proc_map_files_get_link")) {
		pr_info("maps filter: hooked proc_map_files_get_link\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc map_files link hook unavailable\n");
	}
	error = lk1337_register_kprobe(&lk1337_map_files_lookup_kp, "proc_map_files_lookup");
	if (!error) {
		pr_info("maps filter: hooked proc_map_files_lookup\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc_map_files_lookup hook unavailable (%d)\n", error);
	}
	error = lk1337_register_kprobe(&lk1337_map_files_instantiate_kp, "proc_map_files_instantiate");
	if (!error) {
		pr_info("maps filter: hooked proc_map_files_instantiate\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc_map_files_instantiate hook unavailable (%d)\n", error);
	}
	error = lk1337_register_kprobe(&lk1337_map_files_fill_cache_kp, "proc_fill_cache");
	if (!error) {
		pr_info("maps filter: hooked proc_fill_cache for map_files readdir\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc_fill_cache hook unavailable (%d)\n", error);
	}
	error = lk1337_register_kprobe(&lk1337_map_files_readlink_kp, "proc_pid_readlink");
	if (!error) {
		pr_info("maps filter: hooked proc_pid_readlink for map_files\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc_pid_readlink hook unavailable (%d)\n", error);
	}

	if (hooks_registered == 0) {
		pr_err("maps filter: no hooks registered, aborting\n");
		return -ENOENT;
	}
	lk1337_maps_filter_enabled = true;

	pr_info("maps filter initialized, %d hooks active, %d built-in patterns\n",
		hooks_registered,
		(int)(sizeof(lk1337_hide_patterns) / sizeof(char *) - 1));
	return 0;
}

/* 清理maps过滤 */
static void lk1337_maps_filter_exit(void)
{
	unsigned long flags;
	int i;

	lk1337_maps_filter_enabled = false;

	/* 卸载所有kprobe */
	unregister_kprobe(&lk1337_show_map_kp);
	unregister_kprobe(&lk1337_show_smap_kp);
	unregister_kprobe(&lk1337_show_smaps_rollup_kp);
	unregister_kprobe(&lk1337_map_files_link_kp);
	unregister_kprobe(&lk1337_map_files_readlink_kp);
	unregister_kprobe(&lk1337_map_files_lookup_kp);
	unregister_kprobe(&lk1337_map_files_instantiate_kp);
	unregister_kprobe(&lk1337_map_files_fill_cache_kp);

	/* 释放自定义规则 */
	raw_spin_lock_irqsave(&lk1337_pattern_lock, flags);
	for (i = 0; i < lk1337_custom_pattern_count; i++) {
		kfree(lk1337_custom_patterns[i]);
		lk1337_custom_patterns[i] = NULL;
	}
	lk1337_custom_pattern_count = 0;
	raw_spin_unlock_irqrestore(&lk1337_pattern_lock, flags);

	pr_info("maps filter unloaded (maps/smaps/smaps_rollup)\n");
}

/* 用户态接口：添加自定义隐藏规则（入库前转小写，路径比较前也转小写） */
static int lk1337_add_hide_pattern(const char *pattern)
{
	char *new_pattern;
	unsigned long flags;
	int error = 0;

	if (!pattern || strlen(pattern) == 0 || strlen(pattern) > 256)
		return -EINVAL;

	new_pattern = kstrdup(pattern, GFP_KERNEL);
	if (!new_pattern)
		return -ENOMEM;
	lk1337_str_tolower(new_pattern);

	raw_spin_lock_irqsave(&lk1337_pattern_lock, flags);
	if (lk1337_custom_pattern_count >= MAX_CUSTOM_PATTERNS) {
		error = -ENOSPC;
	} else {
		lk1337_custom_patterns[lk1337_custom_pattern_count++] = new_pattern;
		pr_info("added custom hide pattern: %s\n", new_pattern);
	}
	raw_spin_unlock_irqrestore(&lk1337_pattern_lock, flags);
	if (error)
		kfree(new_pattern);

	return error;
}

/* 用户态接口：移除自定义隐藏规则 */
static int lk1337_remove_hide_pattern(const char *pattern)
{
	char needle[257];
	unsigned long flags;
	int i, found = -1;

	if (!pattern || strlen(pattern) > 256)
		return -EINVAL;
	strscpy(needle, pattern, sizeof(needle));
	lk1337_str_tolower(needle);

	raw_spin_lock_irqsave(&lk1337_pattern_lock, flags);
	for (i = 0; i < lk1337_custom_pattern_count; i++) {
		if (lk1337_custom_patterns[i] &&
		    strcmp(lk1337_custom_patterns[i], needle) == 0) {
			found = i;
			break;
		}
	}

	if (found >= 0) {
		kfree(lk1337_custom_patterns[found]);
		/* 移动后续元素 */
		for (i = found; i < lk1337_custom_pattern_count - 1; i++)
			lk1337_custom_patterns[i] = lk1337_custom_patterns[i + 1];
		lk1337_custom_patterns[--lk1337_custom_pattern_count] = NULL;
		pr_info("removed custom hide pattern: %s\n", needle);
	}
	raw_spin_unlock_irqrestore(&lk1337_pattern_lock, flags);

	return found >= 0 ? 0 : -ENOENT;
}

/* 用户态接口：清空所有自定义规则 */
static void lk1337_clear_hide_patterns(void)
{
	unsigned long flags;
	int i;

	raw_spin_lock_irqsave(&lk1337_pattern_lock, flags);
	for (i = 0; i < lk1337_custom_pattern_count; i++) {
		kfree(lk1337_custom_patterns[i]);
		lk1337_custom_patterns[i] = NULL;
	}
	lk1337_custom_pattern_count = 0;
	raw_spin_unlock_irqrestore(&lk1337_pattern_lock, flags);

	pr_info("cleared all custom hide patterns\n");
}

/* 用户态接口：添加过滤PID */
static int lk1337_add_filter_pid(pid_t pid)
{
	unsigned long flags;
	int error = 0;

	if (pid <= 0)
		return -EINVAL;

	raw_spin_lock_irqsave(&lk1337_pid_lock, flags);
	if (lk1337_filter_pid_count >= MAX_FILTER_PIDS) {
		error = -ENOSPC;
	} else {
		lk1337_filter_pids[lk1337_filter_pid_count++] = pid;
		pr_info("added filter PID: %d\n", pid);
	}
	raw_spin_unlock_irqrestore(&lk1337_pid_lock, flags);

	return error;
}

/* 用户态接口：移除过滤PID */
static int lk1337_remove_filter_pid(pid_t pid)
{
	unsigned long flags;
	int i, found = -1;

	if (pid <= 0)
		return -EINVAL;

	raw_spin_lock_irqsave(&lk1337_pid_lock, flags);
	for (i = 0; i < lk1337_filter_pid_count; i++) {
		if (lk1337_filter_pids[i] == pid) {
			found = i;
			break;
		}
	}

	if (found >= 0) {
		/* 移动后续元素 */
		for (i = found; i < lk1337_filter_pid_count - 1; i++)
			lk1337_filter_pids[i] = lk1337_filter_pids[i + 1];
		lk1337_filter_pid_count--;
		pr_info("removed filter PID: %d\n", pid);
	}
	raw_spin_unlock_irqrestore(&lk1337_pid_lock, flags);

	return found >= 0 ? 0 : -ENOENT;
}

/* 用户态接口：清空所有过滤PID */
static void lk1337_clear_filter_pids(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&lk1337_pid_lock, flags);
	lk1337_filter_pid_count = 0;
	raw_spin_unlock_irqrestore(&lk1337_pid_lock, flags);

	pr_info("cleared all filter PIDs\n");
}

/* 用户态接口：设置全局过滤模式 */
static void lk1337_set_filter_all(bool enable)
{
	WRITE_ONCE(lk1337_filter_all_pids, enable);
	pr_info("filter all PIDs: %s\n", enable ? "enabled" : "disabled");
}

#endif
