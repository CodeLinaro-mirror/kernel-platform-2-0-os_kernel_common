// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE-BPF: Filesystem in Userspace with BPF
 * Copyright (c) 2021 Google LLC
 */

#include "fuse_i.h"

#include <linux/fdtable.h>
#include <linux/filter.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/bpf_fuse.h>

struct bpf_prog *fuse_get_bpf_prog(struct file *file)
{
	struct bpf_prog *bpf_prog = ERR_PTR(-EINVAL);

	if (!file || IS_ERR(file))
		return bpf_prog;

	/**
	 * Two ways of getting a bpf prog from another task's fd, since
	 * bpf_prog_get_type_dev only works with an fd
	 *
	 * 1) Duplicate a little of the needed code. Requires access to
	 *    bpf_prog_fops for validation, which is not exported for modules
	 * 2) Insert the bpf_file object into a fd from the current task
	 *    Stupidly complex, but I think OK, as security checks are not run
	 *    during the existence of the handle
	 *
	 * Best would be to upstream 1) into kernel/bpf/syscall.c and export it
	 * for use here. Failing that, we have to use 2, since fuse must be
	 * compilable as a module.
	 */
#if 0
	if (file->f_op != &bpf_prog_fops)
		goto out;

	bpf_prog = file->private_data;
	if (bpf_prog->type == BPF_PROG_TYPE_FUSE)
		bpf_prog_inc(bpf_prog);
	else
		bpf_prog = ERR_PTR(-EINVAL);

#else
	{
		int task_fd = get_unused_fd_flags(file->f_flags);

		if (task_fd < 0)
			goto out;

		fd_install(task_fd, file);

		bpf_prog = bpf_prog_get_type_dev(task_fd, BPF_PROG_TYPE_FUSE,
						 false);

		/* Close the fd, which also closes the file */
		close_fd(task_fd);
		file = NULL;
	}
#endif

out:
	if (file)
		fput(file);
	return bpf_prog;
}

ssize_t fuse_backing_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct fuse_file *ff = file->private_data;
	struct inode *fuse_inode = file_inode(file);
	struct file *backing_file = ff->backing_file;
	struct inode *backing_inode = file_inode(backing_file);

	if (!backing_file->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(backing_file);

	ret = call_mmap(vma->vm_file, vma);

	if (ret)
		fput(backing_file);
	else
		fput(file);

	if (file->f_flags & O_NOATIME)
		return ret;

	if ((!timespec64_equal(&fuse_inode->i_mtime, &backing_inode->i_mtime) ||
	     !timespec64_equal(&fuse_inode->i_ctime,
			       &backing_inode->i_ctime))) {
		fuse_inode->i_mtime = backing_inode->i_mtime;
		fuse_inode->i_ctime = backing_inode->i_ctime;
	}
	touch_atime(&file->f_path);

	return ret;
}

/*******************************************************************************
 * Directory operations after here                                             *
 ******************************************************************************/

int fuse_lookup_initialize_in(struct bpf_fuse_args *fa, struct fuse_lookup_io *fli,
			      struct inode *dir, struct dentry *entry, unsigned int flags)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(dir)->nodeid,
		.opcode = FUSE_LOOKUP,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_lookup_initialize_out(struct bpf_fuse_args *fa, struct fuse_lookup_io *fli,
			       struct inode *dir, struct dentry *entry, unsigned int flags)
{
	fa->out_numargs = 2;
	fa->flags = FUSE_BPF_OUT_ARGVAR;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(fli->feo),
		.value = &fli->feo,
	};
	fa->out_args[1] = (struct bpf_fuse_arg) {
		.size = sizeof(fli->feb.out),
		.value = &fli->feb.out,
	};

	return 0;
}

int fuse_lookup_backing(struct bpf_fuse_args *fa, struct inode *dir,
			struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *fuse_entry = get_fuse_dentry(entry);
	struct fuse_dentry *dir_fuse_entry = get_fuse_dentry(entry->d_parent);
	struct dentry *dir_backing_entry = dir_fuse_entry->backing_path.dentry;
	struct inode *dir_backing_inode = dir_backing_entry->d_inode;
	struct dentry *backing_entry;

	/* TODO this will not handle lookups over mount points */
	inode_lock_nested(dir_backing_inode, I_MUTEX_PARENT);
	backing_entry = lookup_one_len(entry->d_name.name, dir_backing_entry,
				       strlen(entry->d_name.name));
	inode_unlock(dir_backing_inode);

	if (IS_ERR(backing_entry))
		return PTR_ERR(backing_entry);

	fuse_entry->backing_path = (struct path) {
		.dentry = backing_entry,
		.mnt = dir_fuse_entry->backing_path.mnt,
	};

	mntget(fuse_entry->backing_path.mnt);
	return 0;
}

struct dentry *fuse_lookup_finalize(struct bpf_fuse_args *fa, struct inode *dir,
				    struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *fd;
	struct dentry *bd;
	struct inode *inode, *backing_inode;
	struct fuse_entry_out *feo = fa->out_args[0].value;
	struct fuse_entry_bpf_out *febo = fa->out_args[1].value;
	struct fuse_entry_bpf *feb = container_of(febo, struct fuse_entry_bpf, out);

	fd = get_fuse_dentry(entry);
	if (!fd)
		return ERR_PTR(-EIO);
	bd = fd->backing_path.dentry;
	if (!bd)
		return ERR_PTR(-ENOENT);
	backing_inode = bd->d_inode;
	if (!backing_inode)
		return 0;

	inode = fuse_iget_backing(dir->i_sb, backing_inode);

	if (IS_ERR(inode))
		return ERR_PTR(PTR_ERR(inode));

	/* TODO Make sure this handles invalid handles */
	/* TODO Do we need the same code in revalidate */
	if (get_fuse_inode(inode)->bpf) {
		bpf_prog_put(get_fuse_inode(inode)->bpf);
		get_fuse_inode(inode)->bpf = NULL;
	}

	switch (febo->bpf_action) {
	case FUSE_ACTION_KEEP:
		get_fuse_inode(inode)->bpf = get_fuse_inode(dir)->bpf;
		if (get_fuse_inode(inode)->bpf)
			bpf_prog_inc(get_fuse_inode(inode)->bpf);
		break;

	case FUSE_ACTION_REMOVE:
		get_fuse_inode(inode)->bpf = NULL;
		break;

	case FUSE_ACTION_REPLACE: {
		struct file *bpf_file = feb->bpf_file;
		struct bpf_prog *bpf_prog = ERR_PTR(-EINVAL);

		if (bpf_file && !IS_ERR(bpf_file))
			bpf_prog = fuse_get_bpf_prog(bpf_file);

		if (IS_ERR(bpf_prog))
			return ERR_PTR(PTR_ERR(bpf_prog));

		get_fuse_inode(inode)->bpf = bpf_prog;
		break;
	}

	default:
		return ERR_PTR(-EIO);
	}

	switch (febo->backing_action) {
	case FUSE_ACTION_KEEP:
		/* backing inode/path are added in fuse_lookup_backing */
		break;

	case FUSE_ACTION_REMOVE:
		iput(get_fuse_inode(inode)->backing_inode);
		get_fuse_inode(inode)->backing_inode = NULL;
		path_put_init(&get_fuse_dentry(entry)->backing_path);
		break;

	case FUSE_ACTION_REPLACE: {
		struct fuse_conn *fc;
		struct file *backing_file;

		fc = get_fuse_mount(dir)->fc;
		backing_file = feb->backing_file;
		if (!backing_file || IS_ERR(backing_file))
			return ERR_PTR(-EIO);

		iput(get_fuse_inode(inode)->backing_inode);
		get_fuse_inode(inode)->backing_inode = backing_file->f_inode;
		ihold(get_fuse_inode(inode)->backing_inode);

		path_put(&get_fuse_dentry(entry)->backing_path);
		get_fuse_dentry(entry)->backing_path = backing_file->f_path;
		path_get(&get_fuse_dentry(entry)->backing_path);

		fput(backing_file);
		break;
	}
	default:
		return ERR_PTR(-EIO);
	}

	get_fuse_inode(inode)->nodeid = feo->nodeid;

	return d_splice_alias(inode, entry);
}

int fuse_revalidate_backing(struct bpf_fuse_args *fa, struct inode *dir,
			    struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *fuse_dentry = get_fuse_dentry(entry);
	struct dentry *backing_entry = fuse_dentry->backing_path.dentry;

	spin_lock(&backing_entry->d_lock);
	if (d_unhashed(backing_entry)) {
		spin_unlock(&backing_entry->d_lock);
		return 0;
	}
	spin_unlock(&backing_entry->d_lock);

	if (unlikely(backing_entry->d_flags & DCACHE_OP_REVALIDATE))
		return backing_entry->d_op->d_revalidate(backing_entry, flags);
	return 1;
}

void *fuse_revalidate_finalize(struct bpf_fuse_args *fa, struct inode *dir,
			       struct dentry *entry, unsigned int flags)
{
	return 0;
}

int fuse_access_initialize_in(struct bpf_fuse_args *fa, struct fuse_access_in *fai,
			      struct inode *inode, int mask)
{
	*fai = (struct fuse_access_in) {
		.mask = mask,
	};

	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_ACCESS,
		.nodeid = get_node_id(inode),
		.in_numargs = 1,
		.in_args[0].size = sizeof(*fai),
		.in_args[0].value = fai,
	};

	return 0;
}

int fuse_access_initialize_out(struct bpf_fuse_args *fa, struct fuse_access_in *fai,
			       struct inode *inode, int mask)
{
	return 0;
}

int fuse_access_backing(struct bpf_fuse_args *fa, struct inode *inode, int mask)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	const struct fuse_access_in *fai = fa->in_args[0].value;

	return inode_permission(&init_user_ns, fi->backing_inode, fai->mask);
}

void *fuse_access_finalize(struct bpf_fuse_args *fa, struct inode *inode, int mask)
{
	return NULL;
}

