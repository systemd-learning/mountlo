/*
    mountlo: userspace loopback mount
    Copyright (C) 2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING
*/

#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include "os.h"
#include "user.h"
#include "kern_util.h"

int fuseserv_writev_file(int fd, const struct iovec *iov, unsigned long count)
{
	int n = writev(fd, iov, count);
	if (n == -1)
		return -errno;
	return n;
}

extern int fuseserv_readv_file(int fd,  struct iovec *iov, unsigned long count)
{
	int n = readv(fd, iov, count);
	if (n == -1)
		return -errno;
	return n;
}
