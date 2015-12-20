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
#include <linux/module.h>
#include <linux/list.h>
/*
 * There is no need to lock the amfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */

struct file *validatePatternFile(const char *fileName)
{
    int err;
    struct file *filp;

    filp = filp_open(fileName, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
		printk("file_validations err: Unable to access file %s %d\n",
			fileName, (int) PTR_ERR(filp));
		err = -ENOENT;
		return ERR_PTR(err);
	}

    if (!filp->f_op || !filp->f_op->read) {
		printk("No read permissions or file does not exist\n");
		err = -EACCES;
		return ERR_PTR(err);
	}
	return filp;
}
static int amfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct file *fp;
	struct path lower_path;
	struct read_1 *k = (struct read_1 *) raw_data;
	char *dev_name = (char *)(k->dev_name);
	struct inode *inode;
	int *pattern_version_number;
	char *file_name = (char *)kzalloc(200, GFP_KERNEL);
    struct pattern_list *p;
	int version;

	strcpy(file_name, (char *)k->pattern_file_name);

	pattern_version_number = kzalloc(sizeof(int), GFP_KERNEL);
    fp = validatePatternFile(file_name);
    if (!IS_ERR(fp)) {
		int err1;
		err1 = fp->f_inode->i_op->getxattr(fp->f_path.dentry,
									AMFS_ATTR_PATTERN_FILE_VERSION_NUMBER,
									&version, sizeof(version));
		if (err1 > 0) {
			printk("Version Number is: %d", version);
			*pattern_version_number = version;
		} else
			*pattern_version_number = 0;
		filp_close(fp, NULL);
    }

	p = (struct pattern_list *)(k->list_pattern);
	if (!dev_name) {
		printk(KERN_ERR
		       "amfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"amfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct amfs_sb_info), GFP_KERNEL);
	if (!AMFS_SB(sb)) {
		printk(KERN_CRIT "amfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	p = (struct pattern_list *)(k->list_pattern);

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	amfs_set_lower_super(sb, lower_sb, p, file_name, pattern_version_number);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &amfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = amfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &amfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	amfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "amfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(AMFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

int wrapfs_read_file(struct file *filp, char *buf, int len)
{
    int err, bytesRead;
    mm_segment_t oldfs;

    if (!filp || IS_ERR(filp)) {
		printk("file_validations err: Unable to access file %d\n",
			(int) PTR_ERR(filp));
		err = -ENOENT;
		return err;
	}
	if (!filp->f_op || !filp->f_op->read) {
		printk("No read permissions or file does not exist\n");
		err = -EACCES;
		return err;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytesRead = vfs_read(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);
	return bytesRead;
}

struct dentry *amfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	const char delimiters[] = "=", pattern_separator[] = "\n";
	char *token, *buf = NULL, *tok, *pattern_db_name;
	struct file *filp;
	struct dentry *err = NULL;
	int bytesRead;
	struct read_1 *read_buffer;
	struct pattern_list *tmp;
	struct pattern_list *mylist;

	pattern_db_name = kstrdup((const char *)raw_data, GFP_KERNEL);
	token = strsep(&pattern_db_name, delimiters);
	if (token == NULL || strcmp(token, "pattdb") != 0) {
		err = ERR_PTR(-EINVAL);
		goto deallocate_file_name;
	}
	token = strsep(&pattern_db_name, delimiters);
	filp = validatePatternFile(token);
	if (IS_ERR(filp)) {
		err = ERR_PTR(PTR_ERR(filp));
		printk("Unable to open pattern file");
		goto deallocate_file_name;
    }
	buf = kzalloc(READ_BUFFER_SIZE, GFP_KERNEL);
	bytesRead = wrapfs_read_file(filp, buf, READ_BUFFER_SIZE);
	if (bytesRead < 0) {
		err = ERR_PTR(bytesRead);
		printk("Unable to read pattern file");
		goto deallocate_read_buffer;
	}

	mylist = (struct pattern_list *)kzalloc(sizeof(struct pattern_list),
										GFP_KERNEL);
	if (!mylist) {
		err = ERR_PTR(-ENOMEM);
		goto deallocate_read_buffer;
	}

	INIT_LIST_HEAD(&(mylist->list));

	tok = strsep(&buf, pattern_separator);
	while (tok != NULL && strcmp(tok, "") != 0) {
		tmp = (struct pattern_list *)kzalloc(sizeof(struct pattern_list),
							GFP_KERNEL);
		if (!tmp) {
			err = ERR_PTR(-ENOMEM);
			goto deallocate_list;
		}
		tmp->pattern_data = tok;
		list_add_tail(&(tmp->list), &(mylist->list));
		tok = strsep(&buf, pattern_separator);
    }

	read_buffer = kzalloc(sizeof(struct read_1), GFP_KERNEL);
	if (!read_buffer) {
		err = ERR_PTR(-ENOMEM);
		goto deallocate_list;
	}
	read_buffer->dev_name = dev_name;
	read_buffer->list_pattern = mylist;
	read_buffer->pattern_file_name = token;
	return mount_nodev(fs_type, flags, (void *)read_buffer,
			   amfs_read_super);

deallocate_list:
	amfs_free_pattern_list(mylist);
deallocate_read_buffer:
	kfree(buf);
deallocate_file_name:
//	kfree(pattern_db_name);

	return err;
}

static struct file_system_type amfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= AMFS_NAME,
	.mount		= amfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(AMFS_NAME);

static int __init init_amfs_fs(void)
{
	int err;

	pr_info("Registering amfs " AMFS_VERSION "\n");

	err = amfs_init_inode_cache();
	if (err)
		goto out;
	err = amfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&amfs_fs_type);
out:
	if (err) {
		amfs_destroy_inode_cache();
		amfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_amfs_fs(void)
{
	amfs_destroy_inode_cache();
	amfs_destroy_dentry_cache();
	unregister_filesystem(&amfs_fs_type);
	pr_info("Completed amfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs " AMFS_VERSION
		   " (http://amfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_amfs_fs);
module_exit(exit_amfs_fs);
