/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#ifdef KERNEL_2_6
#include <linux/moduleparam.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#else
#include <linux/proc_fs.h>
#include "compat/parser.h"
#endif

MODULE_AUTHOR("Miklos Szeredi <miklos@szeredi.hu>");
MODULE_DESCRIPTION("Filesystem in Userspace");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

spinlock_t fuse_lock;
static kmem_cache_t *fuse_inode_cachep;
static int mount_count;

static int user_allow_other;
#ifdef KERNEL_2_6
module_param(user_allow_other, int, 0644);
#else
MODULE_PARM(user_allow_other, "i");
#endif
MODULE_PARM_DESC(user_allow_other, "Allow non root user to specify the \"allow_other\" or \"allow_root\" mount options");

static int mount_max = 1000;
#ifdef KERNEL_2_6
module_param(mount_max, int, 0644);
#else
MODULE_PARM(mount_max, "i");
#endif
MODULE_PARM_DESC(mount_max, "Maximum number of FUSE mounts allowed, if -1 then unlimited (default: 1000)");

#define FUSE_SUPER_MAGIC 0x65735546

#ifndef KERNEL_2_6
#define kstatfs statfs
#endif
#ifndef FS_SAFE
#define FS_SAFE 0
#endif
#ifndef MAX_LFS_FILESIZE
#define MAX_LFS_FILESIZE (((u64)PAGE_CACHE_SIZE << (BITS_PER_LONG-1))-1)
#endif
struct fuse_mount_data {
	int fd;
	unsigned rootmode;
	unsigned user_id;
	unsigned flags;
	unsigned max_read;
};

static struct inode *fuse_alloc_inode(struct super_block *sb)
{
	struct inode *inode;
	struct fuse_inode *fi;

	inode = kmem_cache_alloc(fuse_inode_cachep, SLAB_KERNEL);
	if (!inode)
		return NULL;

#ifndef KERNEL_2_6
	inode->u.generic_ip = NULL;
#endif
	fi = get_fuse_inode(inode);
	fi->i_time = jiffies - 1;
	fi->nodeid = 0;
	fi->forget_req = fuse_request_alloc();
	if (!fi->forget_req) {
		kmem_cache_free(fuse_inode_cachep, inode);
		return NULL;
	}

	return inode;
}

static void fuse_destroy_inode(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	if (fi->forget_req)
		fuse_request_free(fi->forget_req);
	kmem_cache_free(fuse_inode_cachep, inode);
}

static void fuse_read_inode(struct inode *inode)
{
	/* No op */
}

void fuse_send_forget(struct fuse_conn *fc, struct fuse_req *req,
		      unsigned long nodeid, int version)
{
	struct fuse_forget_in *inarg = &req->misc.forget_in;
	inarg->version = version;
	req->in.h.opcode = FUSE_FORGET;
	req->in.h.nodeid = nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_forget_in);
	req->in.args[0].value = inarg;
	request_send_noreply(fc, req);
}

static void fuse_clear_inode(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	if (fc) {
		struct fuse_inode *fi = get_fuse_inode(inode);
		fuse_send_forget(fc, fi->forget_req, fi->nodeid, inode->i_version);
		fi->forget_req = NULL;
	}
}

void fuse_change_attributes(struct inode *inode, struct fuse_attr *attr)
{
	if (S_ISREG(inode->i_mode) && i_size_read(inode) != attr->size)
#ifdef KERNEL_2_6
		invalidate_inode_pages(inode->i_mapping);
#else
		invalidate_inode_pages(inode);
#endif

	inode->i_ino     = attr->ino;
	inode->i_mode    = (inode->i_mode & S_IFMT) + (attr->mode & 07777);
	inode->i_nlink   = attr->nlink;
	inode->i_uid     = attr->uid;
	inode->i_gid     = attr->gid;
	i_size_write(inode, attr->size);
	inode->i_blksize = PAGE_CACHE_SIZE;
	inode->i_blocks  = attr->blocks;
#ifdef KERNEL_2_6
	inode->i_atime.tv_sec   = attr->atime;
	inode->i_atime.tv_nsec  = attr->atimensec;
	inode->i_mtime.tv_sec   = attr->mtime;
	inode->i_mtime.tv_nsec  = attr->mtimensec;
	inode->i_ctime.tv_sec   = attr->ctime;
	inode->i_ctime.tv_nsec  = attr->ctimensec;
#else
	inode->i_atime   = attr->atime;
	inode->i_mtime   = attr->mtime;
	inode->i_ctime   = attr->ctime;
#endif
}

static void fuse_init_inode(struct inode *inode, struct fuse_attr *attr)
{
	inode->i_mode = attr->mode & S_IFMT;
	i_size_write(inode, attr->size);
	if (S_ISREG(inode->i_mode)) {
		fuse_init_common(inode);
		fuse_init_file_inode(inode);
	} else if (S_ISDIR(inode->i_mode))
		fuse_init_dir(inode);
	else if (S_ISLNK(inode->i_mode))
		fuse_init_symlink(inode);
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		 S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		fuse_init_common(inode);
		init_special_inode(inode, inode->i_mode,
				   new_decode_dev(attr->rdev));
	} else {
		/* Don't let user create weird files */
		inode->i_mode = S_IFREG;
		fuse_init_common(inode);
		fuse_init_file_inode(inode);
	}
}

#ifdef KERNEL_2_6
static int fuse_inode_eq(struct inode *inode, void *_nodeidp)
{
	unsigned long nodeid = *(unsigned long *) _nodeidp;
	if (get_node_id(inode) == nodeid)
		return 1;
	else
		return 0;
}

static int fuse_inode_set(struct inode *inode, void *_nodeidp)
{
	unsigned long nodeid = *(unsigned long *) _nodeidp;
	get_fuse_inode(inode)->nodeid = nodeid;
	return 0;
}

struct inode *fuse_iget(struct super_block *sb, unsigned long nodeid,
			int generation, struct fuse_attr *attr, int version)
{
	struct inode *inode;
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	int retried = 0;

 retry:
	inode = iget5_locked(sb, nodeid, fuse_inode_eq, fuse_inode_set, &nodeid);
	if (!inode)
		return NULL;

	if ((inode->i_state & I_NEW)) {
		inode->i_generation = generation;
		inode->i_data.backing_dev_info = &fc->bdi;
		fuse_init_inode(inode, attr);
		unlock_new_inode(inode);
	} else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		BUG_ON(retried);
		/* Inode has changed type, any I/O on the old should fail */
		make_bad_inode(inode);
		iput(inode);
		retried = 1;
		goto retry;
	}

	fuse_change_attributes(inode, attr);
	inode->i_version = version;
	return inode;
}
#else
static int fuse_inode_eq(struct inode *inode, unsigned long ino, void *_nodeidp){
	unsigned long nodeid = *(unsigned long *) _nodeidp;
	if (inode->u.generic_ip && get_node_id(inode) == nodeid)
		return 1;
	else
		return 0;
}

struct inode *fuse_iget(struct super_block *sb, unsigned long nodeid,
			int generation, struct fuse_attr *attr, int version)
{
	struct inode *inode;
	int retried = 0;

 retry:
	inode = iget4(sb, attr->ino, fuse_inode_eq, &nodeid);
	if (!inode)
		return NULL;

	if (!inode->u.generic_ip) {
		get_fuse_inode(inode)->nodeid = nodeid;
		inode->u.generic_ip = inode;
		inode->i_generation = generation;
		fuse_init_inode(inode, attr);
	} else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		BUG_ON(retried);
		/* Inode has changed type, any I/O on the old should fail */
		remove_inode_hash(inode);
		make_bad_inode(inode);
		iput(inode);
		retried = 1;
		goto retry;
	}

	fuse_change_attributes(inode, attr);
	inode->i_version = version;
	return inode;
}
#endif

static void fuse_put_super(struct super_block *sb)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);

	spin_lock(&fuse_lock);
	mount_count --;
	fc->sb = NULL;
	fc->user_id = 0;
	fc->flags = 0;
	/* Flush all readers on this fs */
	wake_up_all(&fc->waitq);
	fuse_release_conn(fc);
	*get_fuse_conn_super_p(sb) = NULL;
	spin_unlock(&fuse_lock);
}

static void convert_fuse_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr)
{
	stbuf->f_type    = FUSE_SUPER_MAGIC;
	stbuf->f_bsize   = attr->bsize;
	stbuf->f_blocks  = attr->blocks;
	stbuf->f_bfree   = attr->bfree;
	stbuf->f_bavail  = attr->bavail;
	stbuf->f_files   = attr->files;
	stbuf->f_ffree   = attr->ffree;
	stbuf->f_namelen = attr->namelen;
	/* fsid is left zero */
}

static int fuse_statfs(struct super_block *sb, struct kstatfs *buf)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct fuse_req *req;
	struct fuse_statfs_out outarg;
	int err;

        req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	req->in.numargs = 0;
	req->in.h.opcode = FUSE_STATFS;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err)
		convert_fuse_statfs(buf, &outarg.st);
	fuse_put_request(fc, req);
	return err;
}

enum {
	OPT_FD,
	OPT_ROOTMODE,
	OPT_USER_ID,
	OPT_DEFAULT_PERMISSIONS,
	OPT_ALLOW_OTHER,
	OPT_ALLOW_ROOT,
	OPT_KERNEL_CACHE,
#ifndef KERNEL_2_6
	OPT_LARGE_READ,
#endif
	OPT_DIRECT_IO,
	OPT_MAX_READ,
	OPT_ERR
};

static match_table_t tokens = {
	{OPT_FD,			"fd=%u"},
	{OPT_ROOTMODE,			"rootmode=%o"},
	{OPT_USER_ID,			"user_id=%u"},
	{OPT_DEFAULT_PERMISSIONS,	"default_permissions"},
	{OPT_ALLOW_OTHER,		"allow_other"},
	{OPT_ALLOW_ROOT,		"allow_root"},
	{OPT_KERNEL_CACHE,		"kernel_cache"},
#ifndef KERNEL_2_6
	{OPT_LARGE_READ,		"large_read"},
#endif
	{OPT_DIRECT_IO,			"direct_io"},
	{OPT_MAX_READ,			"max_read=%u"},
	{OPT_ERR,			NULL}
};

static int parse_fuse_opt(char *opt, struct fuse_mount_data *d)
{
	char *p;
	memset(d, 0, sizeof(struct fuse_mount_data));
	d->fd = -1;
	d->max_read = ~0;

	while ((p = strsep(&opt, ",")) != NULL) {
		int token;
		int value;
		substring_t args[MAX_OPT_ARGS];
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case OPT_FD:
			if (match_int(&args[0], &value))
				return 0;
			d->fd = value;
			break;

		case OPT_ROOTMODE:
			if (match_octal(&args[0], &value))
				return 0;
			d->rootmode = value;
			break;

		case OPT_USER_ID:
			if (match_int(&args[0], &value))
				return 0;
			d->user_id = value;
			break;

		case OPT_DEFAULT_PERMISSIONS:
			d->flags |= FUSE_DEFAULT_PERMISSIONS;
			break;

		case OPT_ALLOW_OTHER:
			d->flags |= FUSE_ALLOW_OTHER;
			break;

		case OPT_ALLOW_ROOT:
			d->flags |= FUSE_ALLOW_ROOT;
			break;

		case OPT_KERNEL_CACHE:
			d->flags |= FUSE_KERNEL_CACHE;
			break;

#ifndef KERNEL_2_6
		case OPT_LARGE_READ:
			d->flags |= FUSE_LARGE_READ;
			break;
#endif
		case OPT_DIRECT_IO:
			d->flags |= FUSE_DIRECT_IO;
			break;

		case OPT_MAX_READ:
			if (match_int(&args[0], &value))
				return 0;
			d->max_read = value;
			break;

		default:
			return 0;
		}
	}
	if (d->fd == -1)
		return 0;

	return 1;
}

static int fuse_show_options(struct seq_file *m, struct vfsmount *mnt)
{
	struct fuse_conn *fc = get_fuse_conn_super(mnt->mnt_sb);

	seq_printf(m, ",user_id=%u", fc->user_id);
	if (fc->flags & FUSE_DEFAULT_PERMISSIONS)
		seq_puts(m, ",default_permissions");
	if (fc->flags & FUSE_ALLOW_OTHER)
		seq_puts(m, ",allow_other");
	if (fc->flags & FUSE_ALLOW_ROOT)
		seq_puts(m, ",allow_root");
	if (fc->flags & FUSE_KERNEL_CACHE)
		seq_puts(m, ",kernel_cache");
#ifndef KERNEL_2_6
	if (fc->flags & FUSE_LARGE_READ)
		seq_puts(m, ",large_read");
#endif
	if (fc->flags & FUSE_DIRECT_IO)
		seq_puts(m, ",direct_io");
	if (fc->max_read != ~0)
		seq_printf(m, ",max_read=%u", fc->max_read);
	return 0;
}

static void free_conn(struct fuse_conn *fc)
{
	while (!list_empty(&fc->unused_list)) {
		struct fuse_req *req;
		req = list_entry(fc->unused_list.next, struct fuse_req, list);
		list_del(&req->list);
		fuse_request_free(req);
	}
	kfree(fc);
}

/* Must be called with the fuse lock held */
void fuse_release_conn(struct fuse_conn *fc)
{
	if (!fc->sb && !fc->file)
		free_conn(fc);
}

static struct fuse_conn *new_conn(void)
{
	struct fuse_conn *fc;

	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	if (fc != NULL) {
		int i;
		memset(fc, 0, sizeof(*fc));
		fc->sb = NULL;
		fc->file = NULL;
		fc->flags = 0;
		fc->user_id = 0;
		init_waitqueue_head(&fc->waitq);
		INIT_LIST_HEAD(&fc->pending);
		INIT_LIST_HEAD(&fc->processing);
		INIT_LIST_HEAD(&fc->unused_list);
		sema_init(&fc->outstanding_sem, 0);
		for (i = 0; i < FUSE_MAX_OUTSTANDING; i++) {
			struct fuse_req *req = fuse_request_alloc();
			if (!req) {
				free_conn(fc);
				return NULL;
			}
			list_add(&req->list, &fc->unused_list);
		}
#ifdef KERNEL_2_6_6_PLUS
		fc->bdi.ra_pages = (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE;
		fc->bdi.unplug_io_fn = default_unplug_io_fn;
#endif
		fc->reqctr = 1;
	}
	return fc;
}

static struct fuse_conn *get_conn(struct file *file, struct super_block *sb)
{
	struct fuse_conn *fc;

	if (file->f_op != &fuse_dev_operations)
		return NULL;
	fc = new_conn();
	if (fc == NULL)
		return NULL;
	spin_lock(&fuse_lock);
	if (file->private_data) {
		free_conn(fc);
		fc = NULL;
	} else {
		file->private_data = fc;
		fc->sb = sb;
		fc->file = file;
	}
	spin_unlock(&fuse_lock);
	return fc;
}

static struct inode *get_root_inode(struct super_block *sb, unsigned mode)
{
	struct fuse_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.mode = mode;
	attr.ino = FUSE_ROOT_ID;
	return fuse_iget(sb, 1, 0, &attr, 0);
}

#ifdef KERNEL_2_6
static struct dentry *fuse_get_dentry(struct super_block *sb, void *vobjp)
{
	__u32 *objp = vobjp;
	unsigned long nodeid = objp[0];
	__u32 generation = objp[1];
	struct inode *inode;
	struct dentry *entry;

	if (nodeid == 0)
		return ERR_PTR(-ESTALE);

	inode = ilookup5(sb, nodeid, fuse_inode_eq, &nodeid);
	if (!inode || inode->i_generation != generation)
		return ERR_PTR(-ESTALE);

	entry = d_alloc_anon(inode);
	if (!entry) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}

	return entry;
}

static int fuse_encode_fh(struct dentry *dentry, __u32 *fh, int *max_len,
			  int connectable)
{
	struct inode *inode = dentry->d_inode;
	int len = *max_len;
	int type = 1;

	if (len < 2 || (connectable && len < 4))
		return 255;

	len = 2;
	fh[0] = get_fuse_inode(inode)->nodeid;
	fh[1] = inode->i_generation;
	if (connectable && !S_ISDIR(inode->i_mode)) {
		struct inode *parent;

		spin_lock(&dentry->d_lock);
		parent = dentry->d_parent->d_inode;
		fh[2] = get_fuse_inode(parent)->nodeid;
		fh[3] = parent->i_generation;
		spin_unlock(&dentry->d_lock);
		len = 4;
		type = 2;
	}
	*max_len = len;
	return type;
}

static struct export_operations fuse_export_operations = {
	.get_dentry	= fuse_get_dentry,
	.encode_fh      = fuse_encode_fh,
};
#endif

static struct super_operations fuse_super_operations = {
	.alloc_inode    = fuse_alloc_inode,
	.destroy_inode  = fuse_destroy_inode,
	.read_inode	= fuse_read_inode,
	.clear_inode	= fuse_clear_inode,
	.put_super	= fuse_put_super,
	.statfs		= fuse_statfs,
	.show_options	= fuse_show_options,
};

static int inc_mount_count(void)
{
	int success = 0;
	spin_lock(&fuse_lock);
	mount_count ++;
	if (mount_max == -1 || mount_count <= mount_max)
		success = 1;
	spin_unlock(&fuse_lock);
	return success;
}

static int fuse_fill_super(struct super_block *sb, void *data, int silent)
{
	struct fuse_conn *fc;
	struct inode *root;
	struct fuse_mount_data d;
	struct file *file;
	int err;

	if (!parse_fuse_opt((char *) data, &d))
		return -EINVAL;

	if (!user_allow_other &&
	    (d.flags & (FUSE_ALLOW_OTHER | FUSE_ALLOW_ROOT)) &&
	    current->uid != 0)
		return -EPERM;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = FUSE_SUPER_MAGIC;
	sb->s_op = &fuse_super_operations;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
#ifdef KERNEL_2_6
	sb->s_export_op = &fuse_export_operations;
#endif

	file = fget(d.fd);
	if (!file)
		return -EINVAL;

	fc = get_conn(file, sb);
	fput(file);
	if (fc == NULL)
		return -EINVAL;

	fc->flags = d.flags;
	fc->user_id = d.user_id;
	fc->max_read = d.max_read;
#ifdef KERNEL_2_6
	if (fc->max_read / PAGE_CACHE_SIZE < fc->bdi.ra_pages)
		fc->bdi.ra_pages = fc->max_read / PAGE_CACHE_SIZE;
#endif
	fc->max_write = FUSE_MAX_IN / 2;

	*get_fuse_conn_super_p(sb) = fc;

	err = -ENFILE;
	if (!inc_mount_count() && current->uid != 0)
		goto err;

	err = -ENOMEM;
	root = get_root_inode(sb, d.rootmode);
	if (root == NULL)
		goto err;

	sb->s_root = d_alloc_root(root);
	if (!sb->s_root) {
		iput(root);
		goto err;
	}
	fuse_send_init(fc);
	return 0;

 err:
	spin_lock(&fuse_lock);
	mount_count --;
	fc->sb = NULL;
	fuse_release_conn(fc);
	spin_unlock(&fuse_lock);
	*get_fuse_conn_super_p(sb) = NULL;
	return err;
}

#ifdef KERNEL_2_6
static struct super_block *fuse_get_sb(struct file_system_type *fs_type,
				       int flags, const char *dev_name,
				       void *raw_data)
{
	return get_sb_nodev(fs_type, flags, raw_data, fuse_fill_super);
}

static struct file_system_type fuse_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuse",
	.get_sb		= fuse_get_sb,
	.kill_sb	= kill_anon_super,
#ifndef FUSE_MAINLINE
	.fs_flags	= FS_SAFE,
#endif
};
#else
static struct super_block *fuse_read_super_compat(struct super_block *sb,
						  void *data, int silent)
{
	int err = fuse_fill_super(sb, data, silent);
	if (err)
		return NULL;
	else
		return sb;
}

static DECLARE_FSTYPE(fuse_fs_type, "fuse", fuse_read_super_compat, 0);
#endif

static void fuse_inode_init_once(void *foo, kmem_cache_t *cachep,
				 unsigned long flags)
{
	struct inode * inode = foo;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR)
		inode_init_once(inode);
}

static int __init fuse_fs_init(void)
{
	int err;

	err = register_filesystem(&fuse_fs_type);
	if (err)
		printk("fuse: failed to register filesystem\n");
	else {
		fuse_inode_cachep = kmem_cache_create("fuse_inode",
						      sizeof(struct fuse_inode),
						      0, SLAB_HWCACHE_ALIGN,
						      fuse_inode_init_once, NULL);
		if (!fuse_inode_cachep) {
			unregister_filesystem(&fuse_fs_type);
			err = -ENOMEM;
		}
	}

	return err;
}

static void fuse_fs_cleanup(void)
{
	unregister_filesystem(&fuse_fs_type);
	kmem_cache_destroy(fuse_inode_cachep);
}

static int __init fuse_init(void)
{
	int res;

	printk("fuse init (API version %i.%i)\n",
	       FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);
#ifndef FUSE_MAINLINE
	printk("fuse distribution version: %s\n", FUSE_VERSION);
#endif

	spin_lock_init(&fuse_lock);
	res = fuse_fs_init();
	if (res)
		goto err;

	res = fuse_dev_init();
	if (res)
		goto err_fs_cleanup;

	return 0;

 err_fs_cleanup:
	fuse_fs_cleanup();
 err:
	return res;
}

static void __exit fuse_exit(void)
{
	printk(KERN_DEBUG "fuse exit\n");

	fuse_fs_cleanup();
	fuse_dev_cleanup();
}

module_init(fuse_init);
module_exit(fuse_exit);
