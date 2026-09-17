#ifndef LK1337_PROCESS_H
#define LK1337_PROCESS_H

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/sched/mm.h>

static int lk1337_module_base(struct lk1337_base *request)
{
	struct pid *target;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	char *name, *path, *resolved;
	int error = -ENOENT;

	name = strndup_user(u64_to_user_ptr(request->name), 256);
	if (IS_ERR(name))
		return PTR_ERR(name);
	target = find_get_pid(request->pid);
	task = get_pid_task(target, PIDTYPE_PID);
	put_pid(target);
	if (!task) {
		kfree(name);
		return -ESRCH;
	}
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm) {
		kfree(name);
		return -ESRCH;
	}
	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path) {
		error = -ENOMEM;
		goto out;
	}
	request->base = 0;
	mmap_read_lock(mm);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!vma->vm_file)
			continue;
		resolved = d_path(&vma->vm_file->f_path, path, PATH_MAX);
		if (!IS_ERR(resolved) && !strcmp(kbasename(resolved), name)) {
			request->base = vma->vm_start;
			error = 0;
			break;
		}
	}
	mmap_read_unlock(mm);
	kfree(path);
out:
	mmput(mm);
	kfree(name);
	return error;
}

#endif
