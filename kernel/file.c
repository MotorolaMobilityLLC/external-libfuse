/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#ifdef KERNEL_2_6
#include <linux/writeback.h>
#include <linux/moduleparam.h>
#endif
#include <asm/uaccess.h>

static int user_mmap;
#ifdef KERNEL_2_6
module_param(user_mmap, int, 0644);
#else
MODULE_PARM(user_mmap, "i");
#define PageUptodate(page) Page_Uptodate(page)
#endif
MODULE_PARM_DESC(user_mmap, "Allow non root user to create a shared writable mapping");

static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
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
	if (fi->nodeid == FUSE_ROOT_ID) {
		int err = fuse_do_getattr(inode);
		if (err)
		 	return err;
	}

	down(&inode->i_sem);
	err = -ERESTARTSYS;
	req = fuse_get_request(fc);
	if (!req)
		goto out;

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
	inarg.flags = file->f_flags & ~O_EXCL;
	req->in.h.opcode = FUSE_OPEN;
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err && !(fc->flags & FUSE_KERNEL_CACHE)) {
#ifdef KERNEL_2_6
		invalidate_inode_pages(inode->i_mapping);
#else
		invalidate_inode_pages(inode);
#endif
	}
	if (err) {
		fuse_request_free(ff->release_req);
		kfree(ff);
	}
	else {
		ff->fh = outarg.fh;
		file->private_data = ff;
		INIT_LIST_HEAD(&ff->ff_list);
	}

 out_put_request:
	fuse_put_request(fc, req);
 out:
	up(&inode->i_sem);
	return err;
}

void fuse_sync_inode(struct inode *inode)
{
#ifdef KERNEL_2_6
	filemap_fdatawrite(inode->i_mapping);
	filemap_fdatawait(inode->i_mapping);
#else
#ifndef NO_MM
	filemap_fdatasync(inode->i_mapping);
	filemap_fdatawait(inode->i_mapping);
#endif
#endif
}

static int fuse_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req = ff->release_req;
	struct fuse_release_in inarg;
	
	down(&inode->i_sem);
	if (file->f_mode & FMODE_WRITE)
		fuse_sync_inode(inode);

	if (!list_empty(&ff->ff_list)) {
		down_write(&fi->write_sem);
		list_del(&ff->ff_list);
		up_write(&fi->write_sem);
	}

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.flags = file->f_flags & ~O_EXCL;
	req->in.h.opcode = FUSE_RELEASE;
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	fuse_put_request(fc, req);
	kfree(ff);
	up(&inode->i_sem);

	/* Return value is ignored by VFS */
	return 0;
}

static int fuse_flush(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req = ff->release_req;
	struct fuse_flush_in inarg;
	int err;
	
	if (fc->no_flush)
		return 0;

	down(&inode->i_sem);
	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	req->in.h.opcode = FUSE_FLUSH;
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_reset_request(req);
	up(&inode->i_sem);
	if (err == -ENOSYS) {
		fc->no_flush = 1;
		err = 0;
	}
	return err;
}

static int fuse_fsync(struct file *file, struct dentry *de, int datasync)
{
	struct inode *inode = de->d_inode;
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_fsync_in inarg;
	int err;
	
	if (fc->no_fsync)
		return 0;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	/* Make sure all writes to this inode are completed before
	   issuing the FSYNC request */
	down_write(&fi->write_sem);
	up_write(&fi->write_sem);

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.datasync = datasync;
	req->in.h.opcode = FUSE_FSYNC;
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (err == -ENOSYS) {
		fc->no_fsync = 1;
		err = 0;
	}
	fuse_put_request(fc, req);
	return err;
}

static void fuse_read_init(struct fuse_req *req, struct file *file,
			   struct inode *inode, loff_t pos, size_t count)
{
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_read_in *inarg = &req->misc.read_in;

	inarg->fh = ff->fh;
	inarg->offset = pos;
	inarg->size = count;
	req->in.h.opcode = FUSE_READ;
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_read_in);
	req->in.args[0].value = inarg;
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = count;
}

static int fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req = fuse_get_request_nonint(fc);
	loff_t pos = (loff_t) page->index << PAGE_CACHE_SHIFT;
	int err;
	
	fuse_read_init(req, file, inode, pos, PAGE_CACHE_SIZE);
	req->out.argpages = 1;
	req->out.page_zeroing = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err)
		SetPageUptodate(page);
	unlock_page(page);
	return err;
}

#ifdef KERNEL_2_6
static void read_pages_end(struct fuse_conn *fc, struct fuse_req *req)
{
	unsigned i;
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (!req->out.h.error)
			SetPageUptodate(page);
		unlock_page(page);
	}
	fuse_put_request(fc, req);
}

static void fuse_send_readpages(struct fuse_req *req, struct file *file,
				struct inode *inode)
{
	struct fuse_conn *fc = INO_FC(inode);
	loff_t pos = (loff_t) req->pages[0]->index << PAGE_CACHE_SHIFT;
	size_t count = req->num_pages << PAGE_CACHE_SHIFT;
	fuse_read_init(req, file, inode, pos, count);
	req->out.argpages = 1;
	req->out.page_zeroing = 1;
	request_send_async(fc, req, read_pages_end);
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
	struct fuse_conn *fc = INO_FC(inode);
	
	if (req->num_pages && 
	    (req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	     (req->num_pages + 1) * PAGE_CACHE_SIZE > fc->max_read ||
	     req->pages[req->num_pages - 1]->index + 1 != page->index)) {
		struct fuse_conn *fc = INO_FC(page->mapping->host);
		fuse_send_readpages(req, data->file, inode);
		data->req = req = fuse_get_request_nonint(fc);
	}
	req->pages[req->num_pages] = page;
	req->num_pages ++;
	return 0;
}

static int fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_readpages_data data;

	data.req = fuse_get_request_nonint(fc);
	data.file = file;
	data.inode = inode;
	
	read_cache_pages(mapping, pages, fuse_readpages_fill, &data);
	if (data.req->num_pages)
		fuse_send_readpages(data.req, file, inode);
	else
		fuse_put_request(fc, data.req);

	return 0;
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

static void fuse_file_read_block(struct fuse_req *req, struct file *file,
				 struct inode *inode, unsigned start,
				 unsigned end)
{
	struct fuse_conn *fc = INO_FC(inode);
	loff_t pos;
	size_t count;
	int index;
	int err = 1;
	int i;

	for (index = start; index < end; index++) {
		struct page *page = grab_cache_page(inode->i_mapping, index);
		if (!page)
			goto out;
		req->pages[req->num_pages++] = page;
	}
	pos = (loff_t) start << PAGE_CACHE_SHIFT;
	count = req->num_pages << PAGE_CACHE_SHIFT;
	fuse_read_init(req, file, inode, pos, count);
	req->out.argpages = 1;
	req->out.page_zeroing = 1;
	request_send(fc, req);
	err = req->out.h.error;
 out:
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (!err)
			SetPageUptodate(page);
		unlock_page(page);
		page_cache_release(page);
	}
}   

static int fuse_file_bigread(struct file *file, struct inode *inode,
			     loff_t pos, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
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
		return -ERESTARTSYS;
	
	for (; starti < endi; starti = nexti) {
		nexti = starti + (FUSE_BLOCK_SIZE >> PAGE_CACHE_SHIFT);
		nexti = min(nexti, endi);
		if (!fuse_is_block_uptodate(inode, starti, nexti)) {
			fuse_file_read_block(req, file, inode, starti, nexti);
			fuse_reset_request(req);
		}
	}
	fuse_put_request(fc, req);
	return 0;
}
#endif /* KERNEL_2_6 */

static void fuse_release_user_pages(struct fuse_req *req)
{
	unsigned i;

	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i]; 
#ifdef KERNEL_2_6
		set_page_dirty_lock(page);
#else
		lock_page(page);
		set_page_dirty(page);
		unlock_page(page);
#endif
		page_cache_release(page);
	}
}

static int fuse_get_user_pages(struct fuse_req *req, char __user *buf,
			       unsigned nbytes)
{
	unsigned long user_addr = (unsigned long) buf;
	unsigned offset = user_addr & ~PAGE_CACHE_MASK;
	int npages;

	nbytes = min(nbytes, (unsigned) FUSE_MAX_PAGES_PER_REQ << PAGE_CACHE_SHIFT);
	npages = (nbytes + offset + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	npages = min(npages, FUSE_MAX_PAGES_PER_REQ);
	npages = get_user_pages(current, current->mm, user_addr, npages, 1, 0,
				req->pages, NULL);
	if (npages < 0)
		return npages;

	req->num_pages = npages;
	req->page_offset = offset;
	return 0;
}

static ssize_t fuse_direct_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	loff_t pos = *ppos;
	ssize_t res = 0;
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	while (count) {
		unsigned nbytes = min(count, fc->max_read);
		unsigned nread;
		unsigned ntmp;
		int err = fuse_get_user_pages(req, buf, nbytes);
		if (err) {
			res = err;
			break;
		}
		ntmp = (req->num_pages << PAGE_CACHE_SHIFT) - req->page_offset;
		nbytes = min(nbytes, ntmp);
		fuse_read_init(req, file, inode, pos, nbytes);
		req->out.argpages = 1;
		request_send(fc, req);
		fuse_release_user_pages(req);
		if (req->out.h.error) {
			if (!res)
				res = req->out.h.error;
			break;
		}
		nread = req->out.args[0].size;
		count -= nread;
		res += nread;
		pos += nread;
		buf += nread;
		if (nread != nbytes)
			break;
		fuse_reset_request(req);
	}
	fuse_put_request(fc, req);
	if (res > 0)
		*ppos += res;

	return res;
}

static ssize_t fuse_file_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	ssize_t res;

	if (fc->flags & FUSE_DIRECT_IO)
		res = fuse_direct_read(file, buf, count, ppos);
	else {
#ifndef KERNEL_2_6
		if (fc->flags & FUSE_LARGE_READ) {
			down(&inode->i_sem);
			res = fuse_file_bigread(file, inode, *ppos, count);
			up(&inode->i_sem);
			if (res)
				return res;
		}
#endif
		res = generic_file_read(file, buf, count, ppos);
	}
	return res;
}  

static ssize_t fuse_send_write(struct fuse_req *req, struct fuse_file *ff,
			       struct inode *inode, const char *buf,
			       loff_t pos, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_write_in inarg;
	struct fuse_write_out outarg;
	ssize_t res;
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.writepage = 0;
	inarg.fh = ff->fh;
	inarg.offset = pos;
	inarg.size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = count;
	req->in.args[1].value = buf;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	res = req->out.h.error;
	if (!res) {
		if (outarg.size > count)
			return -EPROTO;
		else
			return outarg.size;
	}
	else
		return res;
}

static int write_buffer(struct inode *inode, struct file *file,
			struct page *page, unsigned offset, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_file *ff = file->private_data;
	char *buffer;
	ssize_t res;
	loff_t pos;
	struct fuse_req *req;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	pos = ((loff_t) page->index << PAGE_CACHE_SHIFT) + offset;
	buffer = kmap(page);
	res = fuse_send_write(req, ff, inode, buffer + offset, pos, count);
	fuse_put_request(fc, req);
	if (res >= 0) {
		if (res < count) {
			printk("fuse: short write\n");
			res = -EPROTO;
		} else
			res = 0;
	}
	kunmap(page);
	if (res)
		SetPageError(page);
	return res;
}

static int get_write_count(struct inode *inode, struct page *page)
{
	unsigned long end_index;
	loff_t size = i_size_read(inode);
	int count;
	
	end_index = size >> PAGE_CACHE_SHIFT;
	if (page->index < end_index)
		count = PAGE_CACHE_SIZE;
	else {
		count = size & (PAGE_CACHE_SIZE - 1);
		if (page->index > end_index || count == 0)
			return 0;
	}
	return count;
}

#ifdef KERNEL_2_6
static void write_page_end(struct fuse_conn *fc, struct fuse_req *req)
{
	struct page *page = req->pages[0];
	struct inode *inode = page->mapping->host;
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_write_out *outarg = req->out.args[0].value;
	if (!req->out.h.error && outarg->size != req->in.args[1].size) {
		printk("fuse: short write\n");
		req->out.h.error = -EPROTO;
	}

	if (req->out.h.error) {
		SetPageError(page);
		if (req->out.h.error == -ENOSPC)
			set_bit(AS_ENOSPC, &page->mapping->flags);
		else
			set_bit(AS_EIO, &page->mapping->flags);
	}
	up_read(&fi->write_sem);

	end_page_writeback(page);
	kunmap(page);
	fuse_put_request(fc, req);
}

static void fuse_send_writepage(struct fuse_req *req, struct inode *inode,
				struct page *page, unsigned count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_write_in *inarg;
	struct fuse_file *ff;
	char *buffer;

	BUG_ON(list_empty(&fi->write_files));
	ff = list_entry(fi->write_files.next, struct fuse_file, ff_list);
	
	inarg = &req->misc.write.in;
	buffer = kmap(page);
	inarg->writepage = 1;
	inarg->fh = ff->fh;
	inarg->offset = ((loff_t) page->index << PAGE_CACHE_SHIFT);
	inarg->size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = fi->nodeid;
	req->in.h.uid = 0;
	req->in.h.gid = 0;
	req->in.h.pid = 0;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(struct fuse_write_in);
	req->in.args[0].value = inarg;
	req->in.args[1].size = count;
	req->in.args[1].value = buffer;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_write_out);
	req->out.args[0].value = &req->misc.write.out;
	req->pages[0] = page;
	request_send_async(fc, req, write_page_end);
}

static int fuse_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_req *req;
	int err;

	err = -EWOULDBLOCK;
	if (wbc->nonblocking)
		req = fuse_get_request_nonblock(fc);
	else
		req = fuse_get_request_nonint(fc);
	if (req) {
		int locked = 1;
		if (wbc->nonblocking)
			locked = down_read_trylock(&fi->write_sem);
		else
			down_read(&fi->write_sem);
		if (locked) {
			unsigned count;
			err = 0;
			count = get_write_count(inode, page);
			if (count) {
				SetPageWriteback(page);		
				fuse_send_writepage(req, inode, page, count);
				goto out;
			}
			up_read(&fi->write_sem);
		}
		fuse_put_request(fc, req);
	}
	if (err == -EWOULDBLOCK) {
#ifdef KERNEL_2_6_6_PLUS
		redirty_page_for_writepage(wbc, page);
#else
		__set_page_dirty_nobuffers(page);
#endif
		err = 0;
	}
 out:
	unlock_page(page);
	return err;
}
#else
static ssize_t fuse_send_writepage(struct fuse_req *req, struct fuse_file *ff,
				   struct inode *inode, const char *buf,
				   loff_t pos, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_write_in inarg;
	struct fuse_write_out outarg;
	ssize_t res;
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.writepage = 1;
	inarg.fh = ff->fh;
	inarg.offset = pos;
	inarg.size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = fi->nodeid;
	req->in.h.uid = 0;
	req->in.h.gid = 0;
	req->in.h.pid = 0;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = count;
	req->in.args[1].value = buf;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	res = req->out.h.error;
	if (!res) {
		if (outarg.size > count)
			return -EPROTO;
		else
			return outarg.size;
	}
	else
		return res;
}

static int write_page_block(struct inode *inode, struct page *page)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	char *buffer;
	ssize_t res;
	loff_t pos;
	unsigned count;
	struct fuse_req *req;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	down_read(&fi->write_sem);
	count = get_write_count(inode, page);
	res = 0;
	if (count) {
		struct fuse_file *ff;
		BUG_ON(list_empty(&fi->write_files));
		ff = list_entry(fi->write_files.next, struct fuse_file, ff_list);
		pos = ((loff_t) page->index << PAGE_CACHE_SHIFT);
		buffer = kmap(page);
		res = fuse_send_writepage(req, ff, inode, buffer, pos, count);
		if (res >= 0) {
			if (res < count) {
				printk("fuse: short write\n");
				res = -EPROTO;
			} else
				res = 0;
		}
	}
	up_read(&fi->write_sem);
	fuse_put_request(fc, req);
	kunmap(page);
	if (res)
		SetPageError(page);
	return res;
}

static int fuse_writepage(struct page *page)
{
	int err = write_page_block(page->mapping->host, page);
	unlock_page(page);
	return err;
}
#endif

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
	struct inode *inode = page->mapping->host;

	err = write_buffer(inode, file, page, offset, to - offset);
	if (!err) {
		loff_t pos = (page->index << PAGE_CACHE_SHIFT) + to;
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
		
		if (offset == 0 && to == PAGE_CACHE_SIZE) {
#ifdef KERNEL_2_6
			clear_page_dirty(page);
#else
			ClearPageDirty(page);
#endif
			SetPageUptodate(page);
		}

	}
	return err;
}

static ssize_t fuse_direct_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_file *ff = file->private_data;
	char *tmpbuf;
	ssize_t res = 0;
	loff_t pos = *ppos;
	struct fuse_req *req;
	size_t max_write = min(fc->max_write, (unsigned) PAGE_SIZE);

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	tmpbuf = (char *) __get_free_page(GFP_KERNEL);
	if (!tmpbuf) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}

	while (count) {
		size_t nbytes = min(max_write, count);
		ssize_t res1;
		if (copy_from_user(tmpbuf, buf, nbytes)) {
			res = -EFAULT;
			break;
		}
		res1 = fuse_send_write(req, ff, inode, tmpbuf, pos, nbytes);
		if (res1 < 0) {
			res = res1;
			break;
		}
		res += res1;
		count -= res1;
		buf += res1;
		pos += res1;
		if (res1 < nbytes)
			break;

		if (count)
			fuse_reset_request(req);
	}
	free_page((unsigned long) tmpbuf);
	fuse_put_request(fc, req);

	if (res > 0) {
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
		*ppos = pos;
	}

	return res;
}

static ssize_t fuse_file_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	
	if (fc->flags & FUSE_DIRECT_IO) {
		ssize_t res;
		down(&inode->i_sem);
		res = fuse_direct_write(file, buf, count, ppos);
		up(&inode->i_sem);
		return res;
	}
	else 
		return generic_file_write(file, buf, count, ppos);
}
			       
static int fuse_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);

	if (fc->flags & FUSE_DIRECT_IO)
		return -ENODEV;
	else {
		if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == 
		    (VM_WRITE | VM_SHARED)) {
			struct fuse_inode *fi = INO_FI(inode);
			struct fuse_file *ff = file->private_data;

			if (!user_mmap && current->uid != 0)
				return -EPERM;

			down_write(&fi->write_sem);
			if (list_empty(&ff->ff_list))
				list_add(&ff->ff_list, &fi->write_files);
			up_write(&fi->write_sem);
		}
		return generic_file_mmap(file, vma);
	}
}

static struct file_operations fuse_file_operations = {
	.read		= fuse_file_read,
	.write		= fuse_file_write,
	.mmap		= fuse_file_mmap,
	.open		= fuse_open,
	.flush		= fuse_flush,
	.release	= fuse_release,
	.fsync		= fuse_fsync,
#ifdef KERNEL_2_6
	.sendfile	= generic_file_sendfile,
#endif
};

static struct address_space_operations fuse_file_aops  = {
	.readpage	= fuse_readpage,
	.writepage	= fuse_writepage,
	.prepare_write	= fuse_prepare_write,
	.commit_write	= fuse_commit_write,
#ifdef KERNEL_2_6
	.readpages	= fuse_readpages,
	.set_page_dirty = __set_page_dirty_nobuffers,
#endif
};

void fuse_init_file_inode(struct inode *inode)
{
	inode->i_fop = &fuse_file_operations;
	inode->i_data.a_ops = &fuse_file_aops;
}
