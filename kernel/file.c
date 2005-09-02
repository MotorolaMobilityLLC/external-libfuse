/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>

#ifndef KERNEL_2_6
#define PageUptodate(page) Page_Uptodate(page)
#define clear_page_dirty(page)	ClearPageDirty(page)
#endif
static struct file_operations fuse_direct_io_file_operations;

int fuse_open_common(struct inode *inode, struct file *file, int isdir)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_open_in inarg;
	struct fuse_open_out outarg;
	struct fuse_file *ff;
	int err;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	/* If opening the root node, no lookup has been performed on
	   it, so the attributes must be refreshed */
	if (get_node_id(inode) == FUSE_ROOT_ID) {
		int err = fuse_do_getattr(inode);
		if (err)
		 	return err;
	}

	req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	err = -ENOMEM;
	ff = kmalloc(sizeof(struct fuse_file), GFP_KERNEL);
	if (!ff)
		goto out_put_request;

	ff->release_req = fuse_request_alloc();
	if (!ff->release_req) {
		kfree(ff);
		goto out_put_request;
	}

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	req->in.h.opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (err) {
		fuse_request_free(ff->release_req);
		kfree(ff);
	} else {
		if (!isdir && (outarg.open_flags & FOPEN_DIRECT_IO))
			file->f_op = &fuse_direct_io_file_operations;
		if (!(outarg.open_flags & FOPEN_KEEP_CACHE)) {
#ifdef KERNEL_2_6
			invalidate_inode_pages(inode->i_mapping);
#else
			invalidate_inode_pages(inode);
#endif
		}
		ff->fh = outarg.fh;
		file->private_data = ff;
	}

 out_put_request:
	fuse_put_request(fc, req);
	return err;
}

int fuse_release_common(struct inode *inode, struct file *file, int isdir)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req = ff->release_req;
	struct fuse_release_in *inarg = &req->misc.release_in;

	inarg->fh = ff->fh;
	inarg->flags = file->f_flags & ~O_EXCL;
	req->in.h.opcode = isdir ? FUSE_RELEASEDIR : FUSE_RELEASE;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_release_in);
	req->in.args[0].value = inarg;
	request_send_background(fc, req);
	kfree(ff);

	/* Return value is ignored by VFS */
	return 0;
}

static int fuse_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, 0);
}

static int fuse_release(struct inode *inode, struct file *file)
{
	return fuse_release_common(inode, file, 0);
}

static int fuse_flush(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_flush_in inarg;
	int err;

	if (fc->no_flush)
		return 0;

	req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	req->in.h.opcode = FUSE_FLUSH;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->file = file;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_flush = 1;
		err = 0;
	}
	return err;
}

int fuse_fsync_common(struct file *file, struct dentry *de, int datasync,
		      int isdir)
{
	struct inode *inode = de->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_fsync_in inarg;
	int err;

	if ((!isdir && fc->no_fsync) || (isdir && fc->no_fsyncdir))
		return 0;

	req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.fsync_flags = datasync ? 1 : 0;
	req->in.h.opcode = isdir ? FUSE_FSYNCDIR : FUSE_FSYNC;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->file = file;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		if (isdir)
			fc->no_fsyncdir = 1;
		else
			fc->no_fsync = 1;
		err = 0;
	}
	return err;
}

static int fuse_fsync(struct file *file, struct dentry *de, int datasync)
{
	return fuse_fsync_common(file, de, datasync, 0);
}

size_t fuse_send_read_common(struct fuse_req *req, struct file *file,
			     struct inode *inode, loff_t pos, size_t count,
			     int isdir)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_read_in inarg;

	memset(&inarg, 0, sizeof(struct fuse_read_in));
	inarg.fh = ff->fh;
	inarg.offset = pos;
	inarg.size = count;
	req->in.h.opcode = isdir ? FUSE_READDIR : FUSE_READ;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->file = file;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_read_in);
	req->in.args[0].value = &inarg;
	req->out.argpages = 1;
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = count;
	request_send(fc, req);
	return req->out.args[0].size;
}

static inline size_t fuse_send_read(struct fuse_req *req, struct file *file,
				    struct inode *inode, loff_t pos,
				    size_t count)
{
	return fuse_send_read_common(req, file, inode, pos, count, 0);
}

static int fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	loff_t pos = (loff_t) page->index << PAGE_CACHE_SHIFT;
	struct fuse_req *req = fuse_get_request(fc);
	int err = -EINTR;
	if (!req)
		goto out;

	req->out.page_zeroing = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	fuse_send_read(req, file, inode, pos, PAGE_CACHE_SIZE);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err)
		SetPageUptodate(page);
	fuse_invalidate_attr(inode); /* atime changed */
 out:
	unlock_page(page);
	return err;
}

#ifdef KERNEL_2_6
static int fuse_send_readpages(struct fuse_req *req, struct file *file,
			       struct inode *inode)
{
	loff_t pos = (loff_t) req->pages[0]->index << PAGE_CACHE_SHIFT;
	size_t count = req->num_pages << PAGE_CACHE_SHIFT;
	unsigned i;
	req->out.page_zeroing = 1;
	fuse_send_read(req, file, inode, pos, count);
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (!req->out.h.error)
			SetPageUptodate(page);
		unlock_page(page);
	}
	return req->out.h.error;
}

struct fuse_readpages_data {
	struct fuse_req *req;
	struct file *file;
	struct inode *inode;
};

static int fuse_readpages_fill(void *_data, struct page *page)
{
	struct fuse_readpages_data *data = _data;
	struct fuse_req *req = data->req;
	struct inode *inode = data->inode;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (req->num_pages &&
	    (req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	     (req->num_pages + 1) * PAGE_CACHE_SIZE > fc->max_read ||
	     req->pages[req->num_pages - 1]->index + 1 != page->index)) {
		int err = fuse_send_readpages(req, data->file, inode);
		if (err) {
			unlock_page(page);
			return err;
		}
		fuse_reset_request(req);
	}
	req->pages[req->num_pages] = page;
	req->num_pages ++;
	return 0;
}

static int fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_readpages_data data;
	int err;
	data.file = file;
	data.inode = inode;
	data.req = fuse_get_request(fc);
	if (!data.req)
		return -EINTR;

	err = read_cache_pages(mapping, pages, fuse_readpages_fill, &data);
	if (!err && data.req->num_pages)
		err = fuse_send_readpages(data.req, file, inode);
	fuse_put_request(fc, data.req);
	fuse_invalidate_attr(inode); /* atime changed */
	return err;
}
#else /* KERNEL_2_6 */
#define FUSE_BLOCK_SHIFT 16
#define FUSE_BLOCK_SIZE (1UL << FUSE_BLOCK_SHIFT)
#define FUSE_BLOCK_MASK (~(FUSE_BLOCK_SIZE-1))
#if (1UL << (FUSE_BLOCK_SHIFT - PAGE_CACHE_SHIFT)) > FUSE_MAX_PAGES_PER_REQ
#error FUSE_BLOCK_SHIFT too large
#endif

static int fuse_is_block_uptodate(struct inode *inode, unsigned start,
				  unsigned end)
{
	int index;

	for (index = start; index < end; index++) {
		struct page *page = find_get_page(inode->i_mapping, index);
		if (!page)
			return 0;
		if (!PageUptodate(page)) {
			page_cache_release(page);
			return 0;
		}
		page_cache_release(page);
	}
	return 1;
}

static int fuse_file_read_block(struct fuse_req *req, struct file *file,
				struct inode *inode, unsigned start,
				unsigned end)
{
	loff_t pos;
	size_t count;
	int index;
	int err = -EBUSY;
	int i;

	for (index = start; index < end; index++) {
		struct page *page = grab_cache_page(inode->i_mapping, index);
		if (!page)
			goto out;
		if (PageUptodate(page)) {
			unlock_page(page);
			page_cache_release(page);
			page = NULL;
		}
		req->pages[req->num_pages++] = page;
	}
	pos = (loff_t) start << PAGE_CACHE_SHIFT;
	count = req->num_pages << PAGE_CACHE_SHIFT;
	fuse_send_read(req, file, inode, pos, count);
	err = req->out.h.error;
 out:
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (page) {
			if (!err)
				SetPageUptodate(page);
			unlock_page(page);
			page_cache_release(page);
		}
	}
	return err;
}

static int fuse_file_bigread(struct file *file, struct inode *inode,
			     loff_t pos, size_t count)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	unsigned starti;
	unsigned endi;
	unsigned nexti;
	struct fuse_req *req;
	loff_t size = i_size_read(inode);
	loff_t end = (pos + count + FUSE_BLOCK_SIZE - 1) & FUSE_BLOCK_MASK;
	end = min(end, size);
	if (end <= pos)
		return 0;

	starti = (pos & FUSE_BLOCK_MASK) >> PAGE_CACHE_SHIFT;
	endi = (end + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	for (; starti < endi; starti = nexti) {
		nexti = starti + (FUSE_BLOCK_SIZE >> PAGE_CACHE_SHIFT);
		nexti = min(nexti, endi);
		if (!fuse_is_block_uptodate(inode, starti, nexti)) {
			if (fuse_file_read_block(req, file, inode, starti, nexti))
				break;

			fuse_reset_request(req);
		}
	}
	fuse_put_request(fc, req);
	return 0;
}
#endif /* KERNEL_2_6 */

static size_t fuse_send_write(struct fuse_req *req, struct file *file,
			      struct inode *inode, loff_t pos, size_t count)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_write_in inarg;
	struct fuse_write_out outarg;

	memset(&inarg, 0, sizeof(struct fuse_write_in));
	inarg.fh = ff->fh;
	inarg.offset = pos;
	inarg.size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->file = file;
	req->in.argpages = 1;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(struct fuse_write_in);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = count;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_write_out);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	return outarg.size;
}

static int fuse_prepare_write(struct file *file, struct page *page,
			      unsigned offset, unsigned to)
{
	/* No op */
	return 0;
}

static int fuse_commit_write(struct file *file, struct page *page,
			     unsigned offset, unsigned to)
{
	int err;
	size_t nres;
	unsigned count = to - offset;
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	loff_t pos = ((loff_t) page->index << PAGE_CACHE_SHIFT) + offset;
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	req->num_pages = 1;
	req->pages[0] = page;
	req->page_offset = offset;
	nres = fuse_send_write(req, file, inode, pos, count);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err && nres != count)
		err = -EIO;
	if (!err) {
		pos += count;
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);

		if (offset == 0 && to == PAGE_CACHE_SIZE) {
			clear_page_dirty(page);
			SetPageUptodate(page);
		}
	}
	fuse_invalidate_attr(inode);
	return err;
}

static void fuse_release_user_pages(struct fuse_req *req, int write)
{
	unsigned i;

	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (write)
			set_page_dirty_lock(page);
		put_page(page);
	}
}

static int fuse_get_user_pages(struct fuse_req *req, const char __user *buf,
			       unsigned nbytes, int write)
{
	unsigned long user_addr = (unsigned long) buf;
	unsigned offset = user_addr & ~PAGE_MASK;
	int npages;

	/* This doesn't work with nfsd */
	if (!current->mm)
		return -EPERM;

	nbytes = min(nbytes, (unsigned) FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT);
	npages = (nbytes + offset + PAGE_SIZE - 1) >> PAGE_SHIFT;
	npages = min(npages, FUSE_MAX_PAGES_PER_REQ);
	down_read(&current->mm->mmap_sem);
	npages = get_user_pages(current, current->mm, user_addr, npages, write,
				0, req->pages, NULL);
	up_read(&current->mm->mmap_sem);
	if (npages < 0)
		return npages;

	req->num_pages = npages;
	req->page_offset = offset;
	return 0;
}

static ssize_t fuse_direct_io(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos, int write)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	size_t nmax = write ? fc->max_write : fc->max_read;
	loff_t pos = *ppos;
	ssize_t res = 0;
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	while (count) {
		size_t tmp;
		size_t nres;
		size_t nbytes = min(count, nmax);
		int err = fuse_get_user_pages(req, buf, nbytes, !write);
		if (err) {
			res = err;
			break;
		}
		tmp = (req->num_pages << PAGE_SHIFT) - req->page_offset;
		nbytes = min(nbytes, tmp);
		if (write)
			nres = fuse_send_write(req, file, inode, pos, nbytes);
		else
			nres = fuse_send_read(req, file, inode, pos, nbytes);
		fuse_release_user_pages(req, !write);
		if (req->out.h.error) {
			if (!res)
				res = req->out.h.error;
			break;
		} else if (nres > nbytes) {
			res = -EIO;
			break;
		}
		count -= nres;
		res += nres;
		pos += nres;
		buf += nres;
		if (nres != nbytes)
			break;
		if (count)
			fuse_reset_request(req);
	}
	fuse_put_request(fc, req);
	if (res > 0) {
		if (write && pos > i_size_read(inode))
			i_size_write(inode, pos);
		*ppos = pos;
	}
	fuse_invalidate_attr(inode);

	return res;
}

static ssize_t fuse_direct_read(struct file *file, char __user *buf,
				     size_t count, loff_t *ppos)
{
	return fuse_direct_io(file, buf, count, ppos, 0);
}

static ssize_t fuse_direct_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	ssize_t res;
	/* Don't allow parallel writes to the same file */
	down(&inode->i_sem);
	res = fuse_direct_io(file, buf, count, ppos, 1);
	up(&inode->i_sem);
	return res;
}

static int default_getlk(struct file *file, struct file_lock *fl)
{
	struct file_lock *cfl = posix_test_lock(file, fl);
	fl->fl_type = F_UNLCK;
	if (cfl)
		*fl = *cfl;
	return 0;
}

static void convert_file_lock(const struct file_lock *fl,
			      struct fuse_file_lock *ffl)
{
	ffl->start = fl->fl_start;
	ffl->end   = fl->fl_end;
	ffl->owner = (unsigned long) fl->fl_owner;
	ffl->pid   = fl->fl_pid;
	ffl->type  = fl->fl_type;
}

static int convert_fuse_file_lock(const struct fuse_file_lock *ffl,
				  struct file_lock *fl)
{
	if (ffl->start < 0 || ffl->end < 0 || ffl->end <= ffl->start)
		return -EIO;

	if (ffl->type != F_UNLCK && ffl->type != F_RDLCK &&
	    ffl->type != F_WRLCK)
		return -EIO;

	fl->fl_start = ffl->start;
	fl->fl_end   = ffl->end;
	fl->fl_owner = (fl_owner_t) (unsigned long) ffl->owner;
	fl->fl_pid   = ffl->pid;
	fl->fl_type  = ffl->type;

	return 0;
}

static int fuse_getlk(struct file *file, struct file_lock *fl)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_lk_in_out arg;
	int err;

	if (fc->no_lk)
		return default_getlk(file, fl);

	req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	memset(&arg, 0, sizeof(arg));
	convert_file_lock(fl, &arg.lk);
	req->in.h.opcode = FUSE_GETLK;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(arg);
	req->in.args[0].value = &arg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(arg);
	req->out.args[0].value = &arg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err)
		err = convert_fuse_file_lock(&arg.lk, fl);
	else if (err == -ENOSYS) {
		fc->no_lk = 1;
		err = default_getlk(file, fl);
	}

	return err;
}

static int fuse_setlk(struct file *file, struct file_lock *fl, int sleep)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_lk_in_out arg;
	int err;

	if (fc->no_lk)
		return -ENOSYS;

	if (!sleep) {
		req = fuse_get_request(fc);
		if (!req)
			return -EINTR;
	} else {
		/* SETLKW can wait indefinately so we do not use up a
		   request from the pool, but allocate an unaccounted
		   new one */
		req = fuse_request_alloc();
		if (!req)
			return -ENOMEM;
		req->unaccounted = 1;
	}

	memset(&arg, 0, sizeof(arg));
	convert_file_lock(fl, &arg.lk);
	req->in.h.opcode = sleep ? FUSE_SETLKW : FUSE_SETLK;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(arg);
	req->in.args[0].value = &arg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS)
		fc->no_lk = 1;

	return err;
}

static int fuse_file_lock(struct file *file, int cmd, struct file_lock *fl)
{
	if (cmd == F_GETLK)
		return fuse_getlk(file, fl);
	else {
#ifdef KERNEL_2_6
		int err =  fuse_setlk(file, fl, fl->fl_flags & FL_SLEEP);
#else
		int err = fuse_setlk(file, fl,
				     cmd == F_SETLKW || cmd == F_SETLKW64);
#endif
#ifdef KERNEL_2_6_9_PLUS
		if (err == -ENOSYS)
			err = posix_lock_file_wait(file, fl);
#else
		if (err == -ENOSYS)
			err = 0;
#endif
		return err;
	}
}

#ifndef KERNEL_2_6
static ssize_t fuse_file_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (fc->flags & FUSE_LARGE_READ) {
		int res;
		down(&inode->i_sem);
		res = fuse_file_bigread(file, inode, *ppos, count);
		up(&inode->i_sem);
		if (res)
			return res;
	}
	return generic_file_read(file, buf, count, ppos);
}
#endif
static int fuse_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED)) {
		if ((vma->vm_flags & VM_WRITE))
			return -ENODEV;
		else
			vma->vm_flags &= ~VM_MAYWRITE;
	}
	return generic_file_mmap(file, vma);
}

#ifdef KERNEL_2_6
static int fuse_set_page_dirty(struct page *page)
{
	printk("fuse_set_page_dirty: should not happen\n");
	dump_stack();
	return 0;
}
#endif

static struct file_operations fuse_file_operations = {
	.llseek		= generic_file_llseek,
#ifdef KERNEL_2_6
	.read		= generic_file_read,
#else
	.read		= fuse_file_read,
#endif
	.write		= generic_file_write,
	.mmap		= fuse_file_mmap,
	.open		= fuse_open,
	.flush		= fuse_flush,
	.release	= fuse_release,
	.fsync		= fuse_fsync,
	.lock		= fuse_file_lock,
#ifdef KERNEL_2_6
	.sendfile	= generic_file_sendfile,
#endif
};

static struct file_operations fuse_direct_io_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= fuse_direct_read,
	.write		= fuse_direct_write,
	.open		= fuse_open,
	.flush		= fuse_flush,
	.release	= fuse_release,
	.fsync		= fuse_fsync,
	.lock		= fuse_file_lock,
	/* no mmap and sendfile */
};

static struct address_space_operations fuse_file_aops  = {
	.readpage	= fuse_readpage,
	.prepare_write	= fuse_prepare_write,
	.commit_write	= fuse_commit_write,
#ifdef KERNEL_2_6
	.readpages	= fuse_readpages,
	.set_page_dirty	= fuse_set_page_dirty,
#endif
};

void fuse_init_file_inode(struct inode *inode)
{
	inode->i_fop = &fuse_file_operations;
	inode->i_data.a_ops = &fuse_file_aops;
}
