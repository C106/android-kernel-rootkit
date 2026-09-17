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
#include "internal.h" /* get_proc_task()/PROC_I for proc map_files inodes */

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
static DEFINE_MUTEX(lk1337_pattern_lock);

/* Per-PID过滤配置 */
#define MAX_FILTER_PIDS 16
static pid_t lk1337_filter_pids[MAX_FILTER_PIDS];
static int lk1337_filter_pid_count = 0;
/* Global filtering is the default once maps hooks are enabled. */
static bool lk1337_filter_all_pids = true;  /* true=全局过滤，false=仅过滤指定PID */
static bool lk1337_maps_filter_enabled;
static DEFINE_MUTEX(lk1337_pid_lock);

/* 检查当前进程是否应该被过滤 */
static bool lk1337_should_filter_current_process(void)
{
	pid_t current_pid = task_pid_vnr(current);
	int i;

	/* 全局过滤模式 */
	if (lk1337_filter_all_pids)
		return true;

	/* 检查当前进程是否在过滤列表中 */
	mutex_lock(&lk1337_pid_lock);
	for (i = 0; i < lk1337_filter_pid_count; i++) {
		if (lk1337_filter_pids[i] == current_pid) {
			mutex_unlock(&lk1337_pid_lock);
			return true;
		}
	}
	mutex_unlock(&lk1337_pid_lock);

	return false;
}

/* 检查VMA路径是否需要隐藏 */
static bool lk1337_should_hide_vma(struct vm_area_struct *vma)
{
	struct file *file;
	char *pathname = NULL, *p;
	char *buf = NULL;
	bool hide = false;
	int i;

	if (!vma)
		return false;

	file = vma->vm_file;
	if (!file)
		return false;  /* 匿名映射不隐藏 */

	buf = kmalloc(PATH_MAX, GFP_ATOMIC);
	if (!buf)
		return false;

	pathname = d_path(&file->f_path, buf, PATH_MAX);
	if (IS_ERR(pathname)) {
		/* d_path失败，尝试用dentry名称 */
		if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
			pathname = (char *)file->f_path.dentry->d_name.name;
			pr_debug("using dentry name: %s\n", pathname);
		} else {
			goto out;
		}
	}

	/* 转小写比较，避免大小写绕过 */
	for (p = pathname; *p; ++p) {
		if (*p >= 'A' && *p <= 'Z')
			*p = *p - 'A' + 'a';
	}

	/* 检查内置规则 */
	for (i = 0; lk1337_hide_patterns[i]; i++) {
		if (strstr(pathname, lk1337_hide_patterns[i])) {
			hide = true;
			pr_info("hiding VMA: %s (matched: %s)\n",
				 pathname, lk1337_hide_patterns[i]);
			goto out;
		}
	}

	/* 检查用户自定义规则 */
	mutex_lock(&lk1337_pattern_lock);
	for (i = 0; i < lk1337_custom_pattern_count; i++) {
		if (lk1337_custom_patterns[i] &&
		    strstr(pathname, lk1337_custom_patterns[i])) {
			hide = true;
			pr_info("hiding VMA: %s (custom: %s)\n",
				 pathname, lk1337_custom_patterns[i]);
			mutex_unlock(&lk1337_pattern_lock);
			goto out;
		}
	}
	mutex_unlock(&lk1337_pattern_lock);

	/* 没有匹配到，记录一下 */
	if (strstr(pathname, "frida") || strstr(pathname, "xposed") ||
	    strstr(pathname, "magisk") || strstr(pathname, "substrate")) {
		pr_info("NOT hiding VMA (should match but didn't): %s\n", pathname);
	}

out:
	kfree(buf);
	return hide;
}

/*
 * Hook show_map_vma() 函数
 * 用于过滤 /proc/pid/maps
 */
static int lk1337_show_map_vma_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct seq_file *m;
	struct vm_area_struct *vma;

	/* 先检查是否应该过滤当前进程 */
	if (!lk1337_should_filter_current_process())
		return 0;  /* 不过滤，继续执行原函数 */

	/* ARM64: x0 = seq_file*, x1 = vma* */
	m = (struct seq_file *)regs->regs[0];
	vma = (struct vm_area_struct *)regs->regs[1];

	/* 检查是否需要隐藏 */
	if (lk1337_should_hide_vma(vma)) {
		/*
		 * 跳过这个VMA的输出：
		 * 设置返回值为0（成功但不输出）
		 * 并跳过原函数执行
		 */
		/* A non-zero kprobe return only suppresses the probe's single-step;
		 * it does not skip the probed function. Return directly to its caller
		 * (all proc show helpers are void) to suppress this VMA line. */
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
	struct seq_file *m;
	struct vm_area_struct *vma;

	/* 先检查是否应该过滤当前进程 */
	if (!lk1337_should_filter_current_process())
		return 0;

	/* ARM64: x0 = seq_file*, x1 = vma*, x2 = private data */
	m = (struct seq_file *)regs->regs[0];
	vma = (struct vm_area_struct *)regs->regs[1];

	/* 检查是否需要隐藏 */
	if (lk1337_should_hide_vma(vma)) {
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
 * Hook show_smaps_rollup() 函数
 * 用于过滤 /proc/pid/smaps_rollup
 *
 * 这个文件显示所有VMA的汇总统计，我们需要重新计算
 * 排除掉隐藏VMA的统计数据
 */
static int lk1337_show_smaps_rollup_pre(struct kprobe *p, struct pt_regs *regs)
{
	/*
	 * smaps_rollup比较复杂，它会遍历所有VMA累加统计
	 * 我们不能简单地跳过，否则会导致统计数据不一致
	 *
	 * 最佳方案：让它正常执行，但在累加时跳过隐藏的VMA
	 * 这需要hook更底层的函数，暂时先让它正常输出
	 *
	 * TODO: hook smap_gather_stats()来过滤统计
	 */
	return 0;
}

static struct kprobe lk1337_show_smaps_rollup_kp = {
	.symbol_name = "show_smaps_rollup",
	.pre_handler = lk1337_show_smaps_rollup_pre,
};

/*
 * 备用方案：如果show_map_vma不存在（某些内核版本），
 * 则hook show_vma_header_prefix
 */
static int lk1337_show_vma_header_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct seq_file *m;
	struct vm_area_struct *vma;

	m = (struct seq_file *)regs->regs[0];
	vma = (struct vm_area_struct *)regs->regs[1];

	if (lk1337_should_hide_vma(vma)) {
		regs->pc = regs->regs[30];
		return 1;
	}

	return 0;
}

static struct kprobe lk1337_show_vma_header_kp = {
	.symbol_name = "show_vma_header_prefix",
	.pre_handler = lk1337_show_vma_header_pre,
};

static bool lk1337_map_files_selected(struct task_struct *task)
{
	int i;
	bool selected = lk1337_filter_all_pids;
	if (selected)
		return true;
	if (!task)
		return false;
	mutex_lock(&lk1337_pid_lock);
	for (i = 0; i < lk1337_filter_pid_count; i++)
		if (lk1337_filter_pids[i] == task_pid_vnr(task)) {
			selected = true;
			break;
		}
	mutex_unlock(&lk1337_pid_lock);
	return selected;
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
	int i; bool selected = false;
	if (!dentry || !dentry->d_parent ||
	    strcmp(dentry->d_parent->d_name.name, "map_files"))
		return 0;
	inode = d_inode(dentry);
	if (!inode) return 0;
	task = get_proc_task(inode);
	if (!task) return 0;
	if (lk1337_filter_all_pids) selected = true;
	else {
		pid_t pid = task_pid_vnr(task);
		mutex_lock(&lk1337_pid_lock);
		for (i = 0; i < lk1337_filter_pid_count; i++) if (lk1337_filter_pids[i] == pid) { selected = true; break; }
		mutex_unlock(&lk1337_pid_lock);
	}
	if (!selected) { put_task_struct(task); return 0; }
	dash = strchr(dentry->d_name.name, '-');
	if (!dash) { put_task_struct(task); return 0; }
	start = simple_strtoul(dentry->d_name.name, &stop, 16);
	if (stop != dash) { put_task_struct(task); return 0; }
	end = simple_strtoul(dash + 1, &stop, 16);
	if (stop == dash + 1 || *stop) { put_task_struct(task); return 0; }
	mm = get_task_mm(task); put_task_struct(task);
	if (!mm) return 0;
	mmap_read_lock(mm); vma = find_vma(mm, start);
	if (vma && vma->vm_start == start && vma->vm_end == end && lk1337_should_hide_vma(vma)) {
		pid_t target_pid = task_pid_vnr(task);
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

	/* Hook 1: show_map_vma - 用于/proc/pid/maps */
	error = register_kprobe(&lk1337_show_map_kp);
	if (error) {
		pr_warn("failed to hook show_map_vma (%d), trying backup\n", error);
		/* 尝试备用方案 */
		error = register_kprobe(&lk1337_show_vma_header_kp);
		if (error) {
			pr_warn("failed to hook show_vma_header_prefix (%d)\n", error);
		} else {
			pr_info("maps filter: using show_vma_header_prefix hook\n");
			hooks_registered++;
		}
	} else {
		pr_info("maps filter: hooked show_map_vma for /proc/pid/maps\n");
		hooks_registered++;
	}

	/* Hook 2: show_smap - 用于/proc/pid/smaps */
	error = register_kprobe(&lk1337_show_smap_kp);
	if (error) {
		pr_warn("failed to hook show_smap (%d), /proc/pid/smaps NOT filtered\n", error);
	} else {
		pr_info("maps filter: hooked show_smap for /proc/pid/smaps\n");
		hooks_registered++;
	}

	/* Hook 3: show_smaps_rollup - 用于/proc/pid/smaps_rollup */
	error = register_kprobe(&lk1337_show_smaps_rollup_kp);
	if (error) {
		pr_warn("failed to hook show_smaps_rollup (%d), /proc/pid/smaps_rollup NOT filtered\n", error);
	} else {
		pr_info("maps filter: hooked show_smaps_rollup for /proc/pid/smaps_rollup\n");
		hooks_registered++;
	}
	if (!register_kprobe(&lk1337_map_files_link_kp)) {
		pr_info("maps filter: hooked proc_map_files_get_link\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc map_files link hook unavailable\n");
	}
	error = register_kprobe(&lk1337_map_files_lookup_kp);
	if (!error) {
		pr_info("maps filter: hooked proc_map_files_lookup\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc_map_files_lookup hook unavailable (%d)\n", error);
	}
	error = register_kprobe(&lk1337_map_files_instantiate_kp);
	if (!error) {
		pr_info("maps filter: hooked proc_map_files_instantiate\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc_map_files_instantiate hook unavailable (%d)\n", error);
	}
	error = register_kprobe(&lk1337_map_files_fill_cache_kp);
	if (!error) {
		pr_info("maps filter: hooked proc_fill_cache for map_files readdir\n");
		hooks_registered++;
	} else {
		pr_warn("maps filter: proc_fill_cache hook unavailable (%d)\n", error);
	}
	error = register_kprobe(&lk1337_map_files_readlink_kp);
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
	int i;
	lk1337_maps_filter_enabled = false;

	/* 卸载所有kprobe */
	unregister_kprobe(&lk1337_show_map_kp);
	unregister_kprobe(&lk1337_show_vma_header_kp);
	unregister_kprobe(&lk1337_show_smap_kp);
	unregister_kprobe(&lk1337_show_smaps_rollup_kp);
	unregister_kprobe(&lk1337_map_files_link_kp);
	unregister_kprobe(&lk1337_map_files_readlink_kp);
	unregister_kprobe(&lk1337_map_files_lookup_kp);
	unregister_kprobe(&lk1337_map_files_instantiate_kp);
	unregister_kprobe(&lk1337_map_files_fill_cache_kp);

	/* 释放自定义规则 */
	mutex_lock(&lk1337_pattern_lock);
	for (i = 0; i < lk1337_custom_pattern_count; i++) {
		kfree(lk1337_custom_patterns[i]);
		lk1337_custom_patterns[i] = NULL;
	}
	lk1337_custom_pattern_count = 0;
	mutex_unlock(&lk1337_pattern_lock);

	pr_info("maps filter unloaded (maps/smaps/smaps_rollup)\n");
}

/* 用户态接口：添加自定义隐藏规则 */
static int lk1337_add_hide_pattern(const char *pattern)
{
	char *new_pattern;
	int error = 0;

	if (!pattern || strlen(pattern) == 0 || strlen(pattern) > 256)
		return -EINVAL;

	new_pattern = kstrdup(pattern, GFP_KERNEL);
	if (!new_pattern)
		return -ENOMEM;

	mutex_lock(&lk1337_pattern_lock);
	if (lk1337_custom_pattern_count >= MAX_CUSTOM_PATTERNS) {
		kfree(new_pattern);
		error = -ENOSPC;
	} else {
		lk1337_custom_patterns[lk1337_custom_pattern_count++] = new_pattern;
		pr_info("added custom hide pattern: %s\n", pattern);
	}
	mutex_unlock(&lk1337_pattern_lock);

	return error;
}

/* 用户态接口：移除自定义隐藏规则 */
static int lk1337_remove_hide_pattern(const char *pattern)
{
	int i, found = -1;

	if (!pattern)
		return -EINVAL;

	mutex_lock(&lk1337_pattern_lock);
	for (i = 0; i < lk1337_custom_pattern_count; i++) {
		if (lk1337_custom_patterns[i] &&
		    strcmp(lk1337_custom_patterns[i], pattern) == 0) {
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
		pr_info("removed custom hide pattern: %s\n", pattern);
	}
	mutex_unlock(&lk1337_pattern_lock);

	return found >= 0 ? 0 : -ENOENT;
}

/* 用户态接口：清空所有自定义规则 */
static void lk1337_clear_hide_patterns(void)
{
	int i;

	mutex_lock(&lk1337_pattern_lock);
	for (i = 0; i < lk1337_custom_pattern_count; i++) {
		kfree(lk1337_custom_patterns[i]);
		lk1337_custom_patterns[i] = NULL;
	}
	lk1337_custom_pattern_count = 0;
	mutex_unlock(&lk1337_pattern_lock);

	pr_info("cleared all custom hide patterns\n");
}

/* 用户态接口：添加过滤PID */
static int lk1337_add_filter_pid(pid_t pid)
{
	int error = 0;

	if (pid <= 0)
		return -EINVAL;

	mutex_lock(&lk1337_pid_lock);
	if (lk1337_filter_pid_count >= MAX_FILTER_PIDS) {
		error = -ENOSPC;
	} else {
		lk1337_filter_pids[lk1337_filter_pid_count++] = pid;
		pr_info("added filter PID: %d\n", pid);
	}
	mutex_unlock(&lk1337_pid_lock);

	return error;
}

/* 用户态接口：移除过滤PID */
static int lk1337_remove_filter_pid(pid_t pid)
{
	int i, found = -1;

	if (pid <= 0)
		return -EINVAL;

	mutex_lock(&lk1337_pid_lock);
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
	mutex_unlock(&lk1337_pid_lock);

	return found >= 0 ? 0 : -ENOENT;
}

/* 用户态接口：清空所有过滤PID */
static void lk1337_clear_filter_pids(void)
{
	mutex_lock(&lk1337_pid_lock);
	lk1337_filter_pid_count = 0;
	mutex_unlock(&lk1337_pid_lock);

	pr_info("cleared all filter PIDs\n");
}

/* 用户态接口：设置全局过滤模式 */
static void lk1337_set_filter_all(bool enable)
{
	lk1337_filter_all_pids = enable;
	pr_info("filter all PIDs: %s\n", enable ? "enabled" : "disabled");
}

#endif
