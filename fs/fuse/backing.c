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

#define FUSE_BPF_IOCB_MASK (IOCB_APPEND | IOCB_DSYNC | IOCB_HIPRI | IOCB_NOWAIT | IOCB_SYNC)

struct fuse_bpf_aio_req {
	struct kiocb iocb;
	refcount_t ref;
	struct kiocb *iocb_orig;
};

static struct kmem_cache *fuse_bpf_aio_request_cachep;

static void fuse_file_accessed(struct file *dst_file, struct file *src_file)
{
	struct inode *dst_inode;
	struct inode *src_inode;

	if (dst_file->f_flags & O_NOATIME)
		return;

	dst_inode = file_inode(dst_file);
	src_inode = file_inode(src_file);

	if ((!timespec64_equal(&dst_inode->i_mtime, &src_inode->i_mtime) ||
	     !timespec64_equal(&dst_inode->i_ctime, &src_inode->i_ctime))) {
		dst_inode->i_mtime = src_inode->i_mtime;
		dst_inode->i_ctime = src_inode->i_ctime;
	}

	touch_atime(&dst_file->f_path);
}

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

int fuse_open_initialize_in(struct bpf_fuse_args *fa, struct fuse_open_io *foio,
			 struct inode *inode, struct file *file, bool isdir)
{
	foio->foi = (struct fuse_open_in) {
		.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY),
	};
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(inode)->nodeid,
		.opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(foio->foi),
			.value = &foio->foi,
		},
	};

	return 0;
}

int fuse_open_initialize_out(struct bpf_fuse_args *fa, struct fuse_open_io *foio,
			 struct inode *inode, struct file *file, bool isdir)
{
	foio->foo = (struct fuse_open_out) { 0 };

	fa->out_numargs = 1;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(foio->foo),
		.value = &foio->foo,
	};

	return 0;
}

int fuse_open_backing(struct bpf_fuse_args *fa,
		      struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	const struct fuse_open_in *foi = fa->in_args[0].value;
	struct fuse_file *ff;
	int retval;
	int mask;
	struct fuse_dentry *fd = get_fuse_dentry(file->f_path.dentry);
	struct file *backing_file;

	ff = fuse_file_alloc(fm);
	if (!ff)
		return -ENOMEM;
	file->private_data = ff;

	switch (foi->flags & O_ACCMODE) {
	case O_RDONLY:
		mask = MAY_READ;
		break;

	case O_WRONLY:
		mask = MAY_WRITE;
		break;

	case O_RDWR:
		mask = MAY_READ | MAY_WRITE;
		break;

	default:
		return -EINVAL;
	}

	retval = inode_permission(&init_user_ns,
				  get_fuse_inode(inode)->backing_inode, mask);
	if (retval)
		return retval;

	backing_file =
		dentry_open(&fd->backing_path, foi->flags, current_cred());

	if (IS_ERR(backing_file)) {
		fuse_file_free(ff);
		file->private_data = NULL;
		return PTR_ERR(backing_file);
	}
	ff->backing_file = backing_file;

	return 0;
}

void *fuse_open_finalize(struct bpf_fuse_args *fa,
		       struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_open_out *foo = fa->out_args[0].value;

	if (ff)
		ff->fh = foo->fh;
	return 0;
}

int fuse_create_open_initialize_in(struct bpf_fuse_args *fa, struct fuse_create_open_io *fcoio,
				   struct inode *dir, struct dentry *entry,
				   struct file *file, unsigned int flags, umode_t mode)
{
	fcoio->fci = (struct fuse_create_in) {
		.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY),
		.mode = mode,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_CREATE,
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(fcoio->fci),
			.value = &fcoio->fci,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_create_open_initialize_out(struct bpf_fuse_args *fa, struct fuse_create_open_io *fcoio,
				    struct inode *dir, struct dentry *entry,
				    struct file *file, unsigned int flags, umode_t mode)
{
	fcoio->feo = (struct fuse_entry_out) { 0 };
	fcoio->foo = (struct fuse_open_out) { 0 };

	fa->out_numargs = 2;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(fcoio->feo),
		.value = &fcoio->feo,
	};
	fa->out_args[1] = (struct bpf_fuse_arg) {
		.size = sizeof(fcoio->foo),
		.value = &fcoio->foo,
	};

	return 0;
}

static int fuse_open_file_backing(struct inode *inode, struct file *file)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct dentry *entry = file->f_path.dentry;
	struct fuse_dentry *fuse_dentry = get_fuse_dentry(entry);
	struct fuse_file *fuse_file;
	struct file *backing_file;

	fuse_file = fuse_file_alloc(fm);
	if (!fuse_file)
		return -ENOMEM;
	file->private_data = fuse_file;

	backing_file = dentry_open(&fuse_dentry->backing_path, file->f_flags,
				   current_cred());
	if (IS_ERR(backing_file)) {
		fuse_file_free(fuse_file);
		file->private_data = NULL;
		return PTR_ERR(backing_file);
	}
	fuse_file->backing_file = backing_file;

	return 0;
}

int fuse_create_open_backing(struct bpf_fuse_args *fa, struct inode *dir, struct dentry *entry,
			     struct file *file, unsigned int flags, umode_t mode)
{
	struct fuse_inode *dir_fuse_inode = get_fuse_inode(dir);
	struct fuse_dentry *dir_fuse_dentry = get_fuse_dentry(entry->d_parent);
	struct dentry *backing_dentry = NULL;
	struct inode *inode = NULL;
	struct dentry *newent;
	int err = 0;
	const struct fuse_create_in *fci = fa->in_args[0].value;

	if (!dir_fuse_inode || !dir_fuse_dentry)
		return -EIO;

	inode_lock_nested(dir_fuse_inode->backing_inode, I_MUTEX_PARENT);
	backing_dentry = lookup_one_len(fa->in_args[1].value,
					dir_fuse_dentry->backing_path.dentry,
					strlen(fa->in_args[1].value));
	inode_unlock(dir_fuse_inode->backing_inode);

	if (IS_ERR(backing_dentry))
		return PTR_ERR(backing_dentry);

	if (d_really_is_positive(backing_dentry)) {
		err = -EIO;
		goto out;
	}

	err = vfs_create(&init_user_ns, dir_fuse_inode->backing_inode,
			 backing_dentry, fci->mode, true);
	if (err)
		goto out;

	if (get_fuse_dentry(entry)->backing_path.dentry)
		path_put(&get_fuse_dentry(entry)->backing_path);
	get_fuse_dentry(entry)->backing_path = (struct path) {
		.mnt = dir_fuse_dentry->backing_path.mnt,
		.dentry = backing_dentry,
	};
	path_get(&get_fuse_dentry(entry)->backing_path);

	inode = fuse_iget_backing(dir->i_sb,
				  get_fuse_dentry(entry)->backing_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	if (get_fuse_inode(inode)->bpf)
		bpf_prog_put(get_fuse_inode(inode)->bpf);
	get_fuse_inode(inode)->bpf = dir_fuse_inode->bpf;
	if (get_fuse_inode(inode)->bpf)
		bpf_prog_inc(dir_fuse_inode->bpf);

	newent = d_splice_alias(inode, entry);
	if (IS_ERR(newent)) {
		err = PTR_ERR(newent);
		goto out;
	}

	entry = newent ? newent : entry;
	err = finish_open(file, entry, fuse_open_file_backing);

out:
	dput(backing_dentry);
	return err;
}

void *fuse_create_open_finalize(struct bpf_fuse_args *fa, struct inode *dir, struct dentry *entry,
				struct file *file, unsigned int flags, umode_t mode)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_inode *fi = get_fuse_inode(file->f_inode);
	struct fuse_entry_out *feo = fa->out_args[0].value;
	struct fuse_open_out *foo = fa->out_args[1].value;

	if (fi)
		fi->nodeid = feo->nodeid;
	if (ff)
		ff->fh = foo->fh;
	return 0;
}

int fuse_release_initialize_in(struct bpf_fuse_args *fa, struct fuse_release_in *fri,
			       struct inode *inode, struct file *file)
{
	struct fuse_file *fuse_file = file->private_data;

	/* Always put backing file whatever bpf/userspace says */
	fput(fuse_file->backing_file);

	*fri = (struct fuse_release_in) {
		.fh = ((struct fuse_file *)(file->private_data))->fh,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(inode)->nodeid,
		.opcode = FUSE_RELEASE,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*fri),
		.in_args[0].value = fri,
	};

	return 0;
}

int fuse_release_initialize_out(struct bpf_fuse_args *fa, struct fuse_release_in *fri,
				struct inode *inode, struct file *file)
{
	return 0;
}

int fuse_releasedir_initialize_in(struct bpf_fuse_args *fa,
				  struct fuse_release_in *fri,
				  struct inode *inode, struct file *file)
{
	struct fuse_file *fuse_file = file->private_data;

	/* Always put backing file whatever bpf/userspace says */
	fput(fuse_file->backing_file);

	*fri = (struct fuse_release_in) {
		.fh = ((struct fuse_file *)(file->private_data))->fh,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(inode)->nodeid,
		.opcode = FUSE_RELEASEDIR,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*fri),
		.in_args[0].value = fri,
	};

	return 0;
}

int fuse_releasedir_initialize_out(struct bpf_fuse_args *fa,
				   struct fuse_release_in *fri,
				   struct inode *inode, struct file *file)
{
	return 0;
}

int fuse_release_backing(struct bpf_fuse_args *fa, struct inode *inode, struct file *file)
{
	return 0;
}

void *fuse_release_finalize(struct bpf_fuse_args *fa, struct inode *inode, struct file *file)
{
	fuse_file_free(file->private_data);
	return NULL;
}

int fuse_lseek_initialize_in(struct bpf_fuse_args *fa, struct fuse_lseek_io *flio,
			     struct file *file, loff_t offset, int whence)
{
	struct fuse_file *fuse_file = file->private_data;

	flio->fli = (struct fuse_lseek_in) {
		.fh = fuse_file->fh,
		.offset = offset,
		.whence = whence,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(file->f_inode),
		.opcode = FUSE_LSEEK,
		.in_numargs = 1,
		.in_args[0].size = sizeof(flio->fli),
		.in_args[0].value = &flio->fli,
	};

	return 0;
}

int fuse_lseek_initialize_out(struct bpf_fuse_args *fa, struct fuse_lseek_io *flio,
			      struct file *file, loff_t offset, int whence)
{
	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(flio->flo);
	fa->out_args[0].value = &flio->flo;

	return 0;
}

int fuse_lseek_backing(struct bpf_fuse_args *fa, struct file *file, loff_t offset, int whence)
{
	const struct fuse_lseek_in *fli = fa->in_args[0].value;
	struct fuse_lseek_out *flo = fa->out_args[0].value;
	struct fuse_file *fuse_file = file->private_data;
	struct file *backing_file = fuse_file->backing_file;
	loff_t ret;

	/* TODO: Handle changing of the file handle */
	if (offset == 0) {
		if (whence == SEEK_CUR) {
			flo->offset = file->f_pos;
			return flo->offset;
		}

		if (whence == SEEK_SET) {
			flo->offset = vfs_setpos(file, 0, 0);
			return flo->offset;
		}
	}

	inode_lock(file->f_inode);
	backing_file->f_pos = file->f_pos;
	ret = vfs_llseek(backing_file, fli->offset, fli->whence);
	flo->offset = ret;
	inode_unlock(file->f_inode);
	return ret;
}

void *fuse_lseek_finalize(struct bpf_fuse_args *fa, struct file *file, loff_t offset, int whence)
{
	struct fuse_lseek_out *flo = fa->out_args[0].value;

	if (!fa->error_in)
		file->f_pos = flo->offset;
	return ERR_PTR(flo->offset);
}

static inline void fuse_bpf_aio_put(struct fuse_bpf_aio_req *aio_req)
{
	if (refcount_dec_and_test(&aio_req->ref))
		kmem_cache_free(fuse_bpf_aio_request_cachep, aio_req);
}

static void fuse_bpf_aio_cleanup_handler(struct fuse_bpf_aio_req *aio_req)
{
	struct kiocb *iocb = &aio_req->iocb;
	struct kiocb *iocb_orig = aio_req->iocb_orig;

	if (iocb->ki_flags & IOCB_WRITE) {
		__sb_writers_acquired(file_inode(iocb->ki_filp)->i_sb,
				      SB_FREEZE_WRITE);
		file_end_write(iocb->ki_filp);
		fuse_copyattr(iocb_orig->ki_filp, iocb->ki_filp);
	}
	iocb_orig->ki_pos = iocb->ki_pos;
	fuse_bpf_aio_put(aio_req);
}

static void fuse_bpf_aio_rw_complete(struct kiocb *iocb, long res, long res2)
{
	struct fuse_bpf_aio_req *aio_req =
		container_of(iocb, struct fuse_bpf_aio_req, iocb);
	struct kiocb *iocb_orig = aio_req->iocb_orig;

	fuse_bpf_aio_cleanup_handler(aio_req);
	iocb_orig->ki_complete(iocb_orig, res, res2);
}

int fuse_file_read_iter_initialize_in(struct bpf_fuse_args *fa, struct fuse_file_read_iter_io *fri,
				      struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	fri->fri = (struct fuse_read_in) {
		.fh = ff->fh,
		.offset = iocb->ki_pos,
		.size = to->count,
	};

	/* TODO we can't assume 'to' is a kvec */
	/* TODO we also can't assume the vector has only one component */
	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_READ,
		.nodeid = ff->nodeid,
		.in_numargs = 1,
		.in_args[0].size = sizeof(fri->fri),
		.in_args[0].value = &fri->fri,
		/*
		 * TODO Design this properly.
		 * Possible approach: do not pass buf to bpf
		 * If going to userland, do a deep copy
		 * For extra credit, do that to/from the vector, rather than
		 * making an extra copy in the kernel
		 */
	};

	return 0;
}

int fuse_file_read_iter_initialize_out(struct bpf_fuse_args *fa, struct fuse_file_read_iter_io *fri,
				       struct kiocb *iocb, struct iov_iter *to)
{
	fri->frio = (struct fuse_read_iter_out) {
		.ret = fri->fri.size,
	};

	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(fri->frio);
	fa->out_args[0].value = &fri->frio;

	return 0;
}

int fuse_file_read_iter_backing(struct bpf_fuse_args *fa, struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_read_iter_out *frio = fa->out_args[0].value;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	ssize_t ret;

	if (!iov_iter_count(to))
		return 0;

	if ((iocb->ki_flags & IOCB_DIRECT) &&
	    (!ff->backing_file->f_mapping->a_ops ||
	     !ff->backing_file->f_mapping->a_ops->direct_IO))
		return -EINVAL;

	/* TODO This just plain ignores any change to fuse_read_in */
	if (is_sync_kiocb(iocb)) {
		ret = vfs_iter_read(ff->backing_file, to, &iocb->ki_pos,
				iocb_to_rw_flags(iocb->ki_flags, FUSE_BPF_IOCB_MASK));
	} else {
		struct fuse_bpf_aio_req *aio_req;

		ret = -ENOMEM;
		aio_req = kmem_cache_zalloc(fuse_bpf_aio_request_cachep, GFP_KERNEL);
		if (!aio_req)
			goto out;

		aio_req->iocb_orig = iocb;
		kiocb_clone(&aio_req->iocb, iocb, ff->backing_file);
		aio_req->iocb.ki_complete = fuse_bpf_aio_rw_complete;
		refcount_set(&aio_req->ref, 2);
		ret = vfs_iocb_iter_read(ff->backing_file, &aio_req->iocb, to);
		fuse_bpf_aio_put(aio_req);
		if (ret != -EIOCBQUEUED)
			fuse_bpf_aio_cleanup_handler(aio_req);
	}

	frio->ret = ret;

	/* TODO Need to point value at the buffer for post-modification */

out:
	fuse_file_accessed(file, ff->backing_file);

	return ret;
}

void *fuse_file_read_iter_finalize(struct bpf_fuse_args *fa,
				   struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_read_iter_out *frio = fa->out_args[0].value;

	return ERR_PTR(frio->ret);
}

int fuse_file_write_iter_initialize_in(struct bpf_fuse_args *fa,
				       struct fuse_file_write_iter_io *fwio,
				       struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	*fwio = (struct fuse_file_write_iter_io) {
		.fwi.fh = ff->fh,
		.fwi.offset = iocb->ki_pos,
		.fwi.size = from->count,
	};

	/* TODO we can't assume 'from' is a kvec */
	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_WRITE,
		.nodeid = ff->nodeid,
		.in_numargs = 2,
		.in_args[0].size = sizeof(fwio->fwi),
		.in_args[0].value = &fwio->fwi,
		.in_args[1].size = fwio->fwi.size,
		.in_args[1].value = from->kvec->iov_base,
	};

	return 0;
}

int fuse_file_write_iter_initialize_out(struct bpf_fuse_args *fa,
					struct fuse_file_write_iter_io *fwio,
					struct kiocb *iocb, struct iov_iter *from)
{
	/* TODO we can't assume 'from' is a kvec */
	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(fwio->fwio);
	fa->out_args[0].value = &fwio->fwio;

	return 0;
}
int fuse_file_write_iter_backing(struct bpf_fuse_args *fa,
				 struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_write_iter_out *fwio = fa->out_args[0].value;
	ssize_t ret;

	if (!iov_iter_count(from))
		return 0;

	/* TODO This just plain ignores any change to fuse_write_in */
	/* TODO uint32_t seems smaller than ssize_t.... right? */
	inode_lock(file_inode(file));

	fuse_copyattr(file, ff->backing_file);

	if (is_sync_kiocb(iocb)) {
		file_start_write(ff->backing_file);
		ret = vfs_iter_write(ff->backing_file, from, &iocb->ki_pos,
					   iocb_to_rw_flags(iocb->ki_flags, FUSE_BPF_IOCB_MASK));
		file_end_write(ff->backing_file);

		/* Must reflect change in size of backing file to upper file */
		if (ret > 0)
			fuse_copyattr(file, ff->backing_file);
	} else {
		struct fuse_bpf_aio_req *aio_req;

		ret = -ENOMEM;
		aio_req = kmem_cache_zalloc(fuse_bpf_aio_request_cachep, GFP_KERNEL);
		if (!aio_req)
			goto out;

		file_start_write(ff->backing_file);
		__sb_writers_release(file_inode(ff->backing_file)->i_sb, SB_FREEZE_WRITE);
		aio_req->iocb_orig = iocb;
		kiocb_clone(&aio_req->iocb, iocb, ff->backing_file);
		aio_req->iocb.ki_complete = fuse_bpf_aio_rw_complete;
		refcount_set(&aio_req->ref, 2);
		ret = vfs_iocb_iter_write(ff->backing_file, &aio_req->iocb, from);
		fuse_bpf_aio_put(aio_req);
		if (ret != -EIOCBQUEUED)
			fuse_bpf_aio_cleanup_handler(aio_req);
	}

out:
	inode_unlock(file_inode(file));
	fwio->ret = ret;
	if (ret < 0)
		return ret;
	return 0;
}

void *fuse_file_write_iter_finalize(struct bpf_fuse_args *fa,
				    struct kiocb *iocb, struct iov_iter *from)
{
	struct fuse_write_iter_out *fwio = fa->out_args[0].value;

	return ERR_PTR(fwio->ret);
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

int fuse_file_fallocate_initialize_in(struct bpf_fuse_args *fa,
				      struct fuse_fallocate_in *ffi,
				      struct file *file, int mode, loff_t offset, loff_t length)
{
	struct fuse_file *ff = file->private_data;

	*ffi = (struct fuse_fallocate_in) {
		.fh = ff->fh,
		.offset = offset,
		.length = length,
		.mode = mode,
	};

	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_FALLOCATE,
		.nodeid = ff->nodeid,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*ffi),
		.in_args[0].value = ffi,
	};

	return 0;
}

int fuse_file_fallocate_initialize_out(struct bpf_fuse_args *fa,
				       struct fuse_fallocate_in *ffi,
				       struct file *file, int mode, loff_t offset, loff_t length)
{
	return 0;
}

int fuse_file_fallocate_backing(struct bpf_fuse_args *fa,
				struct file *file, int mode, loff_t offset, loff_t length)
{
	const struct fuse_fallocate_in *ffi = fa->in_args[0].value;
	struct fuse_file *ff = file->private_data;

	return vfs_fallocate(ff->backing_file, ffi->mode, ffi->offset,
			     ffi->length);
}

void *fuse_file_fallocate_finalize(struct bpf_fuse_args *fa,
				   struct file *file, int mode, loff_t offset, loff_t length)
{
	return NULL;
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

int fuse_mknod_initialize_in(struct bpf_fuse_args *fa, struct fuse_mknod_in *fmi,
			     struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	*fmi = (struct fuse_mknod_in) {
		.mode = mode,
		.rdev = new_encode_dev(rdev),
		.umask = current_umask(),
	};
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_MKNOD,
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(*fmi),
			.value = fmi,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_mknod_initialize_out(struct bpf_fuse_args *fa, struct fuse_mknod_in *fmi,
			      struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	return 0;
}

int fuse_mknod_backing(struct bpf_fuse_args *fa,
		       struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	int err = 0;
	const struct fuse_mknod_in *fmi = fa->in_args[0].value;
	struct inode *backing_inode = get_fuse_inode(dir)->backing_inode;
	struct path backing_path;
	struct inode *inode = NULL;

	//TODO Actually deal with changing the backing entry in mknod
	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	mode = fmi->mode;
	if (!IS_POSIXACL(backing_inode))
		mode &= ~fmi->umask;
	err = vfs_mknod(&init_user_ns, backing_inode, backing_path.dentry, mode,
			new_decode_dev(fmi->rdev));
	inode_unlock(backing_inode);
	if (err)
		goto out;
	if (d_really_is_negative(backing_path.dentry) ||
	    unlikely(d_unhashed(backing_path.dentry))) {
		err = -EINVAL;
		/**
		 * TODO: overlayfs responds to this situation with a
		 * lookupOneLen. Should we do that too?
		 */
		goto out;
	}
	inode = fuse_iget_backing(dir->i_sb, backing_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}
	d_instantiate(entry, inode);
out:
	path_put(&backing_path);
	return err;
}

void *fuse_mknod_finalize(struct bpf_fuse_args *fa,
			  struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	return NULL;
}

int fuse_mkdir_initialize_in(struct bpf_fuse_args *fa, struct fuse_mkdir_in *fmi,
			     struct inode *dir, struct dentry *entry, umode_t mode)
{
	*fmi = (struct fuse_mkdir_in) {
		.mode = mode,
		.umask = current_umask(),
	};
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_MKDIR,
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(*fmi),
			.value = fmi,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_mkdir_initialize_out(struct bpf_fuse_args *fa, struct fuse_mkdir_in *fmi,
			      struct inode *dir, struct dentry *entry, umode_t mode)
{
	return 0;
}

int fuse_mkdir_backing(struct bpf_fuse_args *fa,
		       struct inode *dir, struct dentry *entry, umode_t mode)
{
	int err = 0;
	const struct fuse_mkdir_in *fmi = fa->in_args[0].value;
	struct inode *backing_inode = get_fuse_inode(dir)->backing_inode;
	struct path backing_path;
	struct inode *inode = NULL;
	struct dentry *d;

	//TODO Actually deal with changing the backing entry in mkdir
	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	mode = fmi->mode;
	if (!IS_POSIXACL(backing_inode))
		mode &= ~fmi->umask;
	err = vfs_mkdir(&init_user_ns, backing_inode, backing_path.dentry,
			mode);
	if (err)
		goto out;
	if (d_really_is_negative(backing_path.dentry) ||
	    unlikely(d_unhashed(backing_path.dentry))) {
		d = lookup_one_len(entry->d_name.name,
				   backing_path.dentry->d_parent,
				   entry->d_name.len);
		if (IS_ERR(d)) {
			err = PTR_ERR(d);
			goto out;
		}
		dput(backing_path.dentry);
		backing_path.dentry = d;
	}
	inode = fuse_iget_backing(dir->i_sb, backing_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}
	d_instantiate(entry, inode);
out:
	inode_unlock(backing_inode);
	path_put(&backing_path);
	return err;
}

void *fuse_mkdir_finalize(struct bpf_fuse_args *fa,
			  struct inode *dir, struct dentry *entry, umode_t mode)
{
	return NULL;
}

int fuse_rmdir_initialize_in(struct bpf_fuse_args *fa, struct fuse_dummy_io *dummy,
			     struct inode *dir, struct dentry *entry)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_RMDIR,
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

int fuse_rmdir_initialize_out(struct bpf_fuse_args *fa, struct fuse_dummy_io *dummy,
			      struct inode *dir, struct dentry *entry)
{
	return 0;
}

int fuse_rmdir_backing(struct bpf_fuse_args *fa,
		       struct inode *dir, struct dentry *entry)
{
	int err = 0;
	struct path backing_path;
	struct dentry *backing_parent_dentry;
	struct inode *backing_inode;

	/* TODO Actually deal with changing the backing entry in rmdir */
	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	/* TODO Not sure if we should reverify like overlayfs, or get inode from d_parent */
	backing_parent_dentry = dget_parent(backing_path.dentry);
	backing_inode = d_inode(backing_parent_dentry);

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	err = vfs_rmdir(&init_user_ns, backing_inode, backing_path.dentry);
	inode_unlock(backing_inode);

	dput(backing_parent_dentry);
	if (!err)
		d_drop(entry);
	path_put(&backing_path);
	return err;
}

void *fuse_rmdir_finalize(struct bpf_fuse_args *fa, struct inode *dir, struct dentry *entry)
{
	return NULL;
}

int fuse_unlink_initialize_in(struct bpf_fuse_args *fa, struct fuse_dummy_io *dummy,
			      struct inode *dir, struct dentry *entry)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_UNLINK,
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

int fuse_unlink_initialize_out(struct bpf_fuse_args *fa, struct fuse_dummy_io *dummy,
			       struct inode *dir, struct dentry *entry)
{
	return 0;
}

int fuse_unlink_backing(struct bpf_fuse_args *fa, struct inode *dir, struct dentry *entry)
{
	int err = 0;
	struct path backing_path;
	struct dentry *backing_parent_dentry;
	struct inode *backing_inode;

	/* TODO Actually deal with changing the backing entry in unlink */
	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	/* TODO Not sure if we should reverify like overlayfs, or get inode from d_parent */
	backing_parent_dentry = dget_parent(backing_path.dentry);
	backing_inode = d_inode(backing_parent_dentry);

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	err = vfs_unlink(&init_user_ns, backing_inode, backing_path.dentry,
			 NULL);
	inode_unlock(backing_inode);

	dput(backing_parent_dentry);
	if (!err)
		d_drop(entry);
	path_put(&backing_path);
	return err;
}

void *fuse_unlink_finalize(struct bpf_fuse_args *fa, struct inode *dir, struct dentry *entry)
{
	return NULL;
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

int __init fuse_bpf_init(void)
{
	fuse_bpf_aio_request_cachep = kmem_cache_create("fuse_bpf_aio_req",
						   sizeof(struct fuse_bpf_aio_req),
						   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!fuse_bpf_aio_request_cachep)
		return -ENOMEM;

	return 0;
}

void __exit fuse_bpf_cleanup(void)
{
	kmem_cache_destroy(fuse_bpf_aio_request_cachep);
}
