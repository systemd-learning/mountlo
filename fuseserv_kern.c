/*
    mountlo: userspace loopback mount
    Copyright (C) 2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING
*/

#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include "os.h"

static int fuseserv_fd[] = {101, 102};
static int fuseserv_idx = -1;

extern int fuseserv_writev_file(int fd, const struct iovec *iov, unsigned long count);
extern int fuseserv_readv_file(int fd,  struct iovec *iov, unsigned long count);
#define MAX_FUSE_IO  0x20000
#define MAX_PAGES    ((MAX_FUSE_IO >> PAGE_SHIFT) + 6)

static int userbuf_to_iov(const char __user *buf, size_t nbytes,
			  struct page *pages[], struct iovec *iov,
			  size_t count, int write)
{
	unsigned long user_addr = (unsigned long) buf;
	unsigned offset = user_addr & ~PAGE_MASK;
	size_t npages = (nbytes + offset + PAGE_SIZE - 1) >> PAGE_SHIFT;
	size_t i;

	if (npages > count)
		return -EINVAL;

	npages = get_user_pages(current, current->mm, user_addr, npages,
				write, 0, pages, NULL);
	if (npages <= 0)
		return npages;

	iov[0].iov_base = kmap(pages[0]) + offset;
	iov[0].iov_len = min((size_t) (PAGE_SIZE - offset), nbytes);
	nbytes -= iov[0].iov_len;
	for (i = 1; i < npages; i++) {
		iov[i].iov_base = kmap(pages[i]);
		iov[i].iov_len = min((size_t) PAGE_SIZE, nbytes);
		nbytes -= PAGE_SIZE;
	}
	return npages;
}

static void release_pages(struct page *pages[], size_t count, int write)
{
	size_t i;
	for (i = 0; i < count; i++) {
		kunmap(pages[i]);
		if (write) {
			flush_dcache_page(pages[i]);
			set_page_dirty_lock(pages[i]);
		}
		put_page(pages[i]);
	}
}

static ssize_t fuseserv_dev_read(struct file *file, char __user *buf,
				 size_t nbytes, loff_t *off)
{
	int npages;
	ssize_t res;
	struct page *pages[MAX_PAGES];
	struct iovec iov[MAX_PAGES];

	npages = userbuf_to_iov(buf, nbytes, pages, iov, MAX_PAGES, 1);
	if (npages <= 0)
		return npages;

	res = fuseserv_readv_file((long) file->private_data, iov, npages);
	release_pages(pages, npages, 1);
	return res;
}

static ssize_t fuseserv_dev_write(struct kiocb *iocb, const struct iovec *iov,
				  unsigned long count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	int npages = 0;
	ssize_t res;
	int i;
	struct page *pages[MAX_PAGES];
	struct iovec kiov[MAX_PAGES];

	for (i = 0; i < count; i++) {
		int n = userbuf_to_iov(iov[i].iov_base, iov[i].iov_len,
				       pages + npages, kiov + npages,
				       MAX_PAGES - npages, 0);
		if (n < 0) {
			release_pages(pages, npages, 0);
			return n;
		}
		npages += n;
	}

	res = fuseserv_writev_file((long) file->private_data, kiov, npages);
	release_pages(pages, npages, 0);
	return res;
}

static int fuseserv_dev_open(struct inode *inode, struct file *file)
{
	fuseserv_idx ++;
        printk("fuseserv_dev_open %i %i\n", fuseserv_idx, fuseserv_fd[fuseserv_idx]);
	if (fuseserv_idx >= 2 || fuseserv_fd[fuseserv_idx] == -1)
		return -EINVAL;

	file->private_data = (void *) (long) fuseserv_fd[fuseserv_idx];
        printk("  fuseserv_dev_open %i %p\n", fuseserv_idx, file->private_data);
	return 0;
}

static int fuseserv_dev_release(struct inode *inode, struct file *file)
{
	os_close_file((long) file->private_data);
	return 0;
}

struct file_operations fuseserv_dev_operations = {
	.owner		= THIS_MODULE,
	.open		= fuseserv_dev_open,
	.release	= fuseserv_dev_release,
	.read		= fuseserv_dev_read,
	.write		= do_sync_write,
	.aio_write	= fuseserv_dev_write,
};

static struct miscdevice fuseserv_miscdevice = {
	.minor = 229, /* reuse FUSE minor number */
	.name  = "fuseserv",
	.fops = &fuseserv_dev_operations,
};

int fuseserv_init(void)
{
	return misc_register(&fuseserv_miscdevice);
}

late_initcall(fuseserv_init);
