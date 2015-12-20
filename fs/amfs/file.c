/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "amfs.h"
#include "amfsctl.h"
#define MINIMUM(a,b) (a<=b?a:b)

/* Function that checks whether a particular file is malicious or not*/

int check_if_file_is_malicious(struct dentry *dentry, int pattern_version)
{
	int read_file_pattern_version_number = 0, bad_file_flag = 0, err1;
	err1 = dentry->d_inode->i_op->getxattr(dentry, AMFS_ATTR_NAME,
										&bad_file_flag,
										sizeof(bad_file_flag));
    if (err1 > 0 && bad_file_flag == ATTR_IS_A_VIRUS) {
		err1 = dentry->d_inode->i_op->getxattr(dentry,
					AMFS_ATTR_VIRUS_FILE_VERSION_NUMBER,
					&read_file_pattern_version_number,
					sizeof(read_file_pattern_version_number));
		if (err1 > 0) {
			if (read_file_pattern_version_number == pattern_version)
				return 0;
		}
	}
	return 1;
}

int mark_file_as_malicious(struct super_block *sb, struct file *fp)
{
	struct dentry *dentry = fp->f_path.dentry;
	int val = ATTR_IS_A_VIRUS;
	int result = fp->f_inode->i_op->setxattr(dentry,
										AMFS_ATTR_NAME,
										&val, sizeof(val), 0);
	if (result == 0) {
		val = *AMFS_SB(sb)->pattern_version_number;
		result = fp->f_inode->i_op->setxattr(dentry,
							AMFS_ATTR_VIRUS_FILE_VERSION_NUMBER,
							&val, sizeof(val), 0);
		return result;
	}
	return result;
}

static ssize_t amfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err, bytes_not_copied;
	struct file *lower_file;
	struct super_block *sb;
	char *kernel_read_buffer;
    struct pattern_list *temp;
    struct list_head *pos;

	#ifdef EXTRA_CREDIT
	char *start_bytes = NULL, *prev_bytes = NULL;
	#endif

	struct dentry *dentry = file->f_path.dentry;
	lower_file = amfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);

    /* Extracting the superblock structure which contains the
    * information about malware words
	*/
    sb = dentry->d_inode->i_sb;

	/* Check if file is infected */
	if (check_if_file_is_malicious(dentry,
			*AMFS_SB(sb)->pattern_version_number) == 0) {
		err = -EPERM;
		goto out;
	}

    kernel_read_buffer = kzalloc(count, GFP_KERNEL);
    if (!kernel_read_buffer) {
		err = -ENOMEM;
		goto out;
    }

    bytes_not_copied = copy_from_user(kernel_read_buffer, buf,
								count);

    if (bytes_not_copied != 0) {
		err = -EINVAL;
		goto clean_kernel_read_buffer;
    }
    list_for_each(pos, &AMFS_SB(sb)->patt_list->list) {
		temp = list_entry(pos, struct pattern_list, list);
		if (strstr(kernel_read_buffer, temp->pattern_data) != 0) {
			mark_file_as_malicious(sb, file);
			err = -EPERM;
			goto clean_kernel_read_buffer;
		}
	}
	#ifdef EXTRA_CREDIT
	prev_bytes = file->f_inode->i_private;
	if (err == PAGE_SIZE) {
		kernel_read_buffer = kernel_read_buffer + PAGE_SIZE - MAX_PATTERN_SIZE;
		strncpy(file->f_inode->i_private, kernel_read_buffer, MAX_PATTERN_SIZE);
		kernel_read_buffer = kernel_read_buffer -
									(PAGE_SIZE - MAX_PATTERN_SIZE);
	}

	/* Comparing against the boundaries of pages */
	if (prev_bytes[0] != 0) {
		start_bytes = kzalloc(2*MAX_PATTERN_SIZE, GFP_KERNEL);
		strncat(start_bytes, prev_bytes, MAX_PATTERN_SIZE);
		strncat(start_bytes, kernel_read_buffer,
					MINIMUM(err, MAX_PATTERN_SIZE));
		list_for_each(pos, &AMFS_SB(sb)->patt_list->list) {
			temp = list_entry(pos, struct pattern_list, list);
			if (strstr(start_bytes, temp->pattern_data) != 0) {
				printk("Hooray");
				mark_file_as_malicious(sb, file);
				err = -EPERM;
				goto clean_start_bytes;
			}
		}
	}
	#endif

	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));
#ifdef EXTRA_CREDIT
clean_start_bytes:
	if (start_bytes)
		kfree(start_bytes);
#endif

clean_kernel_read_buffer:
	kfree(kernel_read_buffer);
out:
	return err;
}

static ssize_t amfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err, bytes_not_copied;
	char *kernel_write_buffer;
	struct file *lower_file;
	struct pattern_list *temp;
    struct list_head *pos;
	struct super_block *sb;
	struct dentry *dentry = file->f_path.dentry;

	#ifdef EXTRA_CREDIT
	char *start_bytes = NULL, *prev_bytes = NULL;
	#endif

	lower_file = amfs_lower_file(file);

	/* Copying the user buffer into kernel space. */
    kernel_write_buffer = kzalloc(count, GFP_KERNEL);
    if (!kernel_write_buffer) {
		err = -ENOMEM;
		goto out;
    }

    bytes_not_copied = copy_from_user(kernel_write_buffer, buf,
								count);

	if (bytes_not_copied != 0) {
		err = -EINVAL;
		goto clean_kernel_write_buffer;
	}
	/* Extracting the superblock structure which contains the
    * information about malware words
	*/
    sb = dentry->d_inode->i_sb;
    list_for_each(pos, &AMFS_SB(sb)->patt_list->list) {
		temp = list_entry(pos, struct pattern_list, list);
		if (strstr(kernel_write_buffer, temp->pattern_data) != 0) {
			mark_file_as_malicious(sb, file);
			break;
		}
    }

	err = vfs_write(lower_file, buf, count, ppos);

	#ifdef EXTRA_CREDIT
	prev_bytes = file->f_inode->i_private;
	if (err == PAGE_SIZE) {
		kernel_write_buffer =
						kernel_write_buffer + PAGE_SIZE - MAX_PATTERN_SIZE;
		strncpy(file->f_inode->i_private,
						kernel_write_buffer, MAX_PATTERN_SIZE);
		kernel_write_buffer = kernel_write_buffer -
									(PAGE_SIZE - MAX_PATTERN_SIZE);
	}

	/* Comparing against the boundaries of pages */
	if (prev_bytes[0] != 0) {
		start_bytes = kzalloc(2*MAX_PATTERN_SIZE, GFP_KERNEL);
		strncat(start_bytes, prev_bytes, MAX_PATTERN_SIZE);
		strncat(start_bytes, kernel_write_buffer,
					MINIMUM(err, MAX_PATTERN_SIZE));
		list_for_each(pos, &AMFS_SB(sb)->patt_list->list) {
			temp = list_entry(pos, struct pattern_list, list);
			if (strstr(start_bytes, temp->pattern_data) != 0) {
				printk("Hooray\n");
				mark_file_as_malicious(sb, file);
				err = -EPERM;
				goto clean_start_bytes;
			}
		}
	}
	#endif

	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(dentry->d_inode,
					file_inode(lower_file));
	}
#ifdef EXTRA_CREDIT
clean_start_bytes:
	if (start_bytes)
		kfree(start_bytes);
#endif

clean_kernel_write_buffer:
	kfree(kernel_write_buffer);
out:
	return err;
}

static struct file *validateOutputFile(const char *fileName, int flags)
{
    int err;
    struct file *filp;

    /*  Creating the output file with the same permissions as that
		of the running process*/

    filp = filp_open(fileName, flags, 0);

    if (!filp || IS_ERR(filp)) {
		printk("file_validations err: Unable to access file %s %d\n",
			fileName, (int) PTR_ERR(filp));
		err = -ENOENT;
		return ERR_PTR(err);
	}

	if (!filp->f_op || !filp->f_op->write) {
		printk("No write permissions or file does not exist\n");
		err = -EACCES;
		return ERR_PTR(err);
	}
	return filp;
}

static int wrapfs_write_file(struct file *filp, char *buf, int len)
{
    int bytesWritten, err;
    mm_segment_t oldfs;

    if (!filp || IS_ERR(filp)) {
		printk("file_validations err: Unable to access output file %d\n",
			(int) PTR_ERR(filp));
		err = -ENOENT;
		return err;
	}

	if (!filp->f_op || !filp->f_op->write) {
		printk("No write permissions or file does not exist\n");
		err = -EACCES;
		return err;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytesWritten = vfs_write(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);
	return bytesWritten;
}

struct amfs_getdents_callback {
    struct dir_context ctx;
    struct dir_context *caller;
    struct dentry *dentry;
	int amfs_pattern_version;
};

static int
amfs_filldir(struct dir_context *ctx, const char *lower_name,
		int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
    struct amfs_getdents_callback *buf =
		container_of(ctx, struct amfs_getdents_callback, ctx);
	struct dentry *lower_dentry;
	struct qstr this;
    int rc = 0, hide_this_file = 0;

    this.name = lower_name;
    this.len = lower_namelen;
    this.hash = full_name_hash(this.name, this.len);
    lower_dentry = d_lookup(buf->dentry, &this);
	if (lower_dentry) {
		if (check_if_file_is_malicious(lower_dentry,
				buf->amfs_pattern_version) == 0)
				hide_this_file = 1;
	}
	buf->caller->pos = buf->ctx.pos;
	if (hide_this_file == 0)
		rc = !dir_emit(buf->caller, lower_name, lower_namelen, ino, d_type);

	return rc;
}

static int amfs_readdir(struct file *file, struct dir_context *ctx)
{
	int rc, pattern_version;
	struct amfs_getdents_callback buf = {
		.ctx.actor = amfs_filldir,
		.caller = ctx,
	};
	struct file *lower_file;
	struct inode *inode = file_inode(file);

	lower_file = amfs_lower_file(file);
	pattern_version = *AMFS_SB(file->f_inode->i_sb)->pattern_version_number;

	buf.dentry = lower_file->f_path.dentry;
	buf.amfs_pattern_version = pattern_version;

	lower_file = amfs_lower_file(file);
	lower_file->f_pos = ctx->pos;
	rc = iterate_dir(lower_file, &buf.ctx);
	ctx->pos = buf.ctx.pos;
	if (rc < 0)
		goto out;
	if (rc >= 0)
		fsstack_copy_attr_atime(inode,
					file_inode(lower_file));
out:
    return rc;
}

static int delete_pattern_from_list(struct super_block *sb, const char *pattern)
{
    char *buf = NULL;
    unsigned int delete_pattern_length = 0;
    struct pattern_list *temp = NULL;
    struct list_head *pos = NULL;
	int pattern_found = 0, err = 0;
	struct list_head *q4;

	delete_pattern_length = strlen_user(pattern);
	buf = kmalloc(delete_pattern_length, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}
	err = copy_from_user(buf, pattern, delete_pattern_length);

	if (err != 0) {
		kfree(buf);
		goto out;
	}

	list_for_each_safe(pos, q4, &AMFS_SB(sb)->patt_list->list) {
		temp = list_entry(pos, struct pattern_list, list);
		if (strcmp(temp->pattern_data, buf) == 0) {
			pattern_found = 1;
			list_del(pos);
			kfree(buf);
			buf = NULL;
			kfree(temp);
			break;
		}
	}
	if (pattern_found == 0) {
		kfree(buf);
		err = -EINVAL;
		goto out;
	}

	/* Increment the pattern version number */
	*AMFS_SB(sb)->pattern_version_number =
			*AMFS_SB(sb)->pattern_version_number + 1;
out:
	return err;
}

static int add_pattern_to_list(struct super_block *sb, const char *pattern)
{
	char *buf = NULL;
	unsigned int add_pattern_length = 0;
	struct pattern_list *temp = NULL;
	int err = 0;

    add_pattern_length = strlen_user(pattern);
	list_for_each_entry(temp, &AMFS_SB(sb)->patt_list->list, list) {
		if (strcmp(temp->pattern_data, pattern) == 0) {
			err = -EINVAL;
			goto out;
		}
	}
    buf = kmalloc(add_pattern_length, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}
    err = copy_from_user(buf, pattern, add_pattern_length);
	if (err != 0) {
		kfree(buf);
		goto out;
	}

    temp = (struct pattern_list *)kzalloc(sizeof(struct pattern_list),
										GFP_KERNEL);
	if (!temp) {
		kfree(buf);
		err = -ENOMEM;
		goto out;
	}
    temp->pattern_data = buf;
    list_add_tail(&(temp->list), &AMFS_SB(sb)->patt_list->list);

    /* Increment the pattern version number*/
	*AMFS_SB(sb)->pattern_version_number =
		*AMFS_SB(sb)->pattern_version_number + 1;
out:
	return err;
}

static long write_to_file(struct super_block *sb, struct file *fp)
{
	struct pattern_list *temp;
	struct list_head *pos;
	int rc;

	list_for_each(pos, &AMFS_SB(sb)->patt_list->list) {
		temp = list_entry(pos, struct pattern_list, list);
		rc = wrapfs_write_file(fp, temp->pattern_data,
							strlen(temp->pattern_data));
		if (rc < 0)
			return rc;
		rc = wrapfs_write_file(fp, "\n", 1);
		if (rc < 0)
			return rc;
	}
	return 0;
}
static long amfs_unlocked_ioctl(struct file *file, unsigned int cmd,
													unsigned long arg)
{
	int count = 0;
	long err = 0;
	struct file *lower_file;
	struct file *pattern_file_pointer = NULL;
	int pattern_file_open_flags = O_TRUNC | O_WRONLY;
	char *buf = NULL;
    struct pattern_list *temp = NULL;

	/* 	Getting the super_block of AMFS filesystem
	* 	which contains the file name and the list of the
	*	malware patterns
	*/
	struct super_block *sb = file->f_inode->i_sb;

	switch (cmd) {
	case AMFS_IOCTL_LIST_PATTERNS:
		list_for_each_entry(temp, &AMFS_SB(sb)->patt_list->list, list) {
			count = count + 1 + strlen(temp->pattern_data);
		}
		buf = kzalloc(count, GFP_KERNEL);
		if (!buf) {
			err = -ENOMEM;
			goto out;
		}
		list_for_each_entry(temp, &AMFS_SB(sb)->patt_list->list, list) {
			strcat(buf, temp->pattern_data);
			strcat(buf, "\n");
		}
		err = copy_to_user((char *)arg, buf, count);
		kfree(buf);
		break;
	case AMFS_IOCTL_ADD_PATTERN:
		err = add_pattern_to_list(sb, (char *) arg);
		if (err == 0) {
			pattern_file_pointer = validateOutputFile
				(AMFS_SB(sb)->pattern_file_name,
				pattern_file_open_flags);
			if (IS_ERR(pattern_file_pointer)) {
				err = PTR_ERR(pattern_file_pointer);
				goto out;
			}
			err = write_to_file(sb, pattern_file_pointer);
			filp_close(pattern_file_pointer, NULL);
		}
		break;
	case AMFS_IOCTL_DELETE_PATTERN:
		err = delete_pattern_from_list(sb, (char *) arg);
		if (err == 0) {
			pattern_file_pointer = validateOutputFile
								(AMFS_SB(sb)->pattern_file_name,
								pattern_file_open_flags);
			if (IS_ERR(pattern_file_pointer)) {
				err = PTR_ERR(pattern_file_pointer);
				goto out;
			}
			err = write_to_file(sb, pattern_file_pointer);
			filp_close(pattern_file_pointer, NULL);
		}
		break;
	default:
		/*	Since this IOCTL command is not a known one, we pass it to the
		* 	lower superblock to handle this ioctl
		*/
		lower_file = amfs_lower_file(file);

		/* XXX: use vfs_ioctl if/when VFS exports it */
		if (!lower_file || !lower_file->f_op) {
			printk("Lower file does not existl\n");
			goto out;
		}
		if (lower_file->f_op->unlocked_ioctl) {
			printk("unlocked_ioctl does not exist\n");
			err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);
		}

		/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
		if (!err)
			fsstack_copy_attr_all(file_inode(file),
						  file_inode(lower_file));
		break;
	}

out:
	return err;
}

#ifdef CONFIG_COMPAT
static long amfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int amfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = amfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "amfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!AMFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "amfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &amfs_vm_ops;

	file->f_mapping->a_ops = &amfs_aops; /* set our aops */
	if (!AMFS_F(file)->lower_vm_ops) /* save for our ->fault */
		AMFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int amfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	#ifdef EXTRA_CREDIT
	file->f_inode->i_private = kzalloc(MAX_PATTERN_SIZE, GFP_KERNEL);
	if (!file->f_inode->i_private) {
		err = -ENOMEM;
		goto out_err;
	}
	*((char *)file->f_inode->i_private) = 0;
	#endif

	file->private_data =
		kzalloc(sizeof(struct amfs_file_info), GFP_KERNEL);
	if (!AMFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link amfs's file struct to lower's */
	amfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = amfs_lower_file(file);
		if (lower_file) {
			amfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		amfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(AMFS_F(file));
	else
		fsstack_copy_attr_all(inode, amfs_lower_inode(inode));
out_err:
	return err;
}

static int amfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	#ifdef EXTRA_CREDIT
	kfree(file->f_inode->i_private);
	#endif
	lower_file = amfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int amfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = amfs_lower_file(file);
	if (lower_file) {
		amfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(AMFS_F(file));
	return 0;
}

static int amfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = amfs_lower_file(file);
	amfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	amfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int amfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

static ssize_t amfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_read)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

static ssize_t amfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_write)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t amfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = amfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Wrapfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
amfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

/*
 * Wrapfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
amfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations amfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= amfs_read,
	.write		= amfs_write,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.mmap		= amfs_mmap,
	.open		= amfs_open,
	.flush		= amfs_flush,
	.release	= amfs_file_release,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
	.aio_read	= amfs_aio_read,
	.aio_write	= amfs_aio_write,
	.read_iter	= amfs_read_iter,
	.write_iter	= amfs_write_iter,
};

/* trimmed directory options */
const struct file_operations amfs_dir_fops = {
	.llseek		= amfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= amfs_readdir,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.open		= amfs_open,
	.release	= amfs_file_release,
	.flush		= amfs_flush,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
};
