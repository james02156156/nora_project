// SPDX-License-Identifier: GPL-2.0

#include <generated/utsrelease.h>
#include "skw_core.h"
#include "skw_dentry.h"
#include "skw_compat.h"
#include "version.h"

static struct dentry *skw_debugfs_root;
static struct proc_dir_entry *skw_proc_root;

static int skw_proc_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, "\n");
	seq_printf(seq, "Kernel Version:  \t%s\n"
			"Wi-Fi Driver:    \t%s\n"
			"Wi-Fi Branch:    \t%s\n",
			UTS_RELEASE,
			SKW_VERSION,
			SKW_BRANCH);

	seq_puts(seq, "\n");
	seq_printf(seq, "STA SME EXTR:    \t%s\n"
			"SAP SME EXTR:    \t%s\n",
			__is_defined(SKW_STA_SME_EXTERNAL) ? "True" : "False",
			__is_defined(SKW_SAP_SME_EXTERNAL) ? "True" : "False");

	seq_puts(seq, "\n");

	return 0;
}

static int skw_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, skw_proc_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_proc_fops = {
	.proc_open = skw_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations skw_proc_fops = {
	.open = skw_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

struct dentry *skw_debugfs_subdir(const char *name, struct dentry *parent)
{
	struct dentry *de, *pentry;

	pentry = parent ? parent : skw_debugfs_root;
	if (!pentry)
		return NULL;

	de = debugfs_create_dir(name, pentry);

	return IS_ERR(de) ? NULL : de;
}

struct dentry *skw_debugfs_file(struct dentry *parent,
				const char *name, umode_t mode,
				const struct file_operations *fops, void *data)
{
	struct dentry *de, *pentry;

	pentry = parent ? parent : skw_debugfs_root;
	if (!pentry)
		return NULL;

	de = debugfs_create_file(name, mode, pentry, data, fops);

	return IS_ERR(de) ? NULL : de;
}

struct proc_dir_entry *skw_procfs_subdir(const char *name,
				struct proc_dir_entry *parent)
{
	struct proc_dir_entry *dentry = parent ? parent : skw_proc_root;

	if (!dentry)
		return NULL;

	return proc_mkdir_data(name, 0, dentry, NULL);
}

struct proc_dir_entry *skw_procfs_file(struct proc_dir_entry *parent,
				       const char *name, umode_t mode,
				       const void *fops, void *data)
{
	struct proc_dir_entry *dentry = parent ? parent : skw_proc_root;

	if (!dentry)
		return NULL;

	return proc_create_data(name, mode, dentry, fops, data);
}

int skw_dentry_init(void)
{
	skw_proc_root = proc_mkdir("skwifi", NULL);
	if (!skw_proc_root)
		pr_err("creat proc skwifi failed\n");

	skw_procfs_file(skw_proc_root, "profile", 0, &skw_proc_fops, NULL);

	skw_debugfs_root = debugfs_create_dir("skwifi", NULL);
	if (IS_ERR(skw_debugfs_root)) {
		pr_err("create skwifi failed, ret: %ld\n",
		       PTR_ERR(skw_debugfs_root));

		skw_debugfs_root = NULL;
	}

	return 0;
}

void skw_dentry_deinit(void)
{
	debugfs_remove_recursive(skw_debugfs_root);
	proc_remove(skw_proc_root);
}
