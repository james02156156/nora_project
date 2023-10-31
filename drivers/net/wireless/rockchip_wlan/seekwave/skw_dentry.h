/* SPDX-License-Identifier: GPL-2.0 */
/******************************************************************************
 *
 * Copyright(c) 2020-2030  Seekwave Corporation.
 *
 *****************************************************************************/
#ifndef __SKW_DENTRY_H__
#define __SKW_DENTRY_H__

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>

static inline void  skw_remove_debugfs(struct dentry *dentry)
{
	debugfs_remove(dentry);
}

struct dentry *skw_debugfs_subdir(const char *name, struct dentry *parent);
struct dentry *skw_debugfs_file(struct dentry *parent,
				const char *name, umode_t mode,
				const struct file_operations *fops, void *data);
struct proc_dir_entry *skw_procfs_subdir(const char *name,
				struct proc_dir_entry *parent);
struct proc_dir_entry *skw_procfs_file(struct proc_dir_entry *parent,
				       const char *name, umode_t mode,
				       const void *proc_fops, void *data);
int skw_dentry_init(void);
void skw_dentry_deinit(void);
#endif
