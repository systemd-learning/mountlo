/*
  mountlo: userspace loopback mount
  Copyright (C) 2005  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING
*/

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64
#include "mountlo-config.h"
#include <fuse.h>
#include <fuse_lowlevel.h>
#include <fuse_opt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>

extern int uml_main(int argc, char **argv, char **envp);

extern void fuse_kern_unmount(const char *mountpoint, int fd);
extern int fuse_kern_mount(const char *mountpoint, struct fuse_args *args);

static void writelast(int fd, char *l, int size)
{
	while(!*l && size)
		l++, size--;
	if (size)
		write(fd, l, size);
}

struct mountlo_config {
	char *image;
	char *mountpoint;
	char *type;
	char *kopts;
	int debug;
	int verbose;
	int foreground;
	unsigned partition;
	unsigned memory;
};

static void usage(const char *progname)
{
	fprintf(stderr,
		"usage: %s [options] image_file mountpoint\n"
		"options:\n"
		"    -h   --help      print help\n"
		"    -V   --version   print version\n"
		"    --foreground     foreground operation\n"
		"    -d               enable debug output\n"
		"    -v               verbose mode\n"
		"    -t type          specify the filesystem type\n"
		"    -p num           select partition to mount\n"
		"    -r               read only\n"
		"    -w               read write\n"
		"    -m megs          allocated memory in Mbytes (default: 10)\n"
		"    -o option        mount option (see man mount)\n",
		progname);
	exit(1);
}

enum {
	KEY_HELP,
	KEY_VERSION,
	KEY_KERN,
	KEY_RO,
	KEY_RW,
};

#define MOUNTLO_OPT(t, p, v) { t, offsetof(struct mountlo_config, p), v }

static struct fuse_opt mountlo_opts[] = {
	MOUNTLO_OPT("-d",              debug,          1),
	MOUNTLO_OPT("-v",              verbose,        1),
	MOUNTLO_OPT("--foreground",    foreground,     1),
	MOUNTLO_OPT("-p %u",           partition,      0),
	MOUNTLO_OPT("-t %s",           type,           0),
	MOUNTLO_OPT("-m %u",           memory,         0),
	FUSE_OPT_KEY("-r",             KEY_RO),
	FUSE_OPT_KEY("-w",             KEY_RW),
	FUSE_OPT_KEY("ro",             KEY_KERN),
	FUSE_OPT_KEY("rw",             KEY_KERN),
	FUSE_OPT_KEY("async",          KEY_KERN),
	FUSE_OPT_KEY("sync",           KEY_KERN),
	FUSE_OPT_KEY("dirsync",        KEY_KERN),
	FUSE_OPT_KEY("atime",          KEY_KERN),
	FUSE_OPT_KEY("noatime",        KEY_KERN),
	FUSE_OPT_KEY("-V",             KEY_VERSION),
	FUSE_OPT_KEY("--version",      KEY_VERSION),
	FUSE_OPT_KEY("-h",             KEY_HELP),
	FUSE_OPT_KEY("--help",         KEY_HELP),
	FUSE_OPT_END
};

static char *do_strdup(const char *s)
{
	char *t = strdup(s);
	if (!t) {
		fprintf(stderr, "failed to allocate memory\n");
		exit(1);
	}
	return t;
}

static void *do_malloc(size_t len)
{
	void *ptr = malloc(len);
	if (!ptr) {
		fprintf(stderr, "memory allocation failed\n");
		exit(1);
	}
	return ptr;
}

static int mountlo_opt_proc(void *data, const char *arg, int key,
			    struct fuse_args *outargs)
{
	struct mountlo_config *conf = data;

	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
		if (!conf->image) {
			conf->image = do_strdup(arg);
			return 0;
		}
		if (!conf->mountpoint) {
			conf->mountpoint = do_strdup(arg);
			return 0;
		}
		break;

	case FUSE_OPT_KEY_OPT:
		return 1;

	case KEY_HELP:
		usage(outargs->argv[0]);

	case KEY_VERSION:
		fprintf(stderr, "mountlo version %s\n", PACKAGE_VERSION);
		exit(0);

	case KEY_RW:
		fuse_opt_add_arg(outargs, "-orw");
		return fuse_opt_add_opt(&conf->kopts, "rw");

	case KEY_RO:
		arg = "ro";
		/* fall through */

	case KEY_KERN:
		return fuse_opt_add_opt(&conf->kopts, arg) == -1 ? -1 : 1;
	}

	fprintf(stderr, "unknown option: `%s'\n", arg);
	return -1;
}

static int mountlo_main(int argc, char **argv, char **envp)
{
	int fd;
	char tmp32[32];
	char *tmp;
	int i;
	unsigned len;
	unsigned tmpi;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_args iargs = FUSE_ARGS_INIT(0, NULL);
	char *iopts = NULL;
	struct fuse_args umlargs = FUSE_ARGS_INIT(0, NULL);
	struct mountlo_config conf;
	int pip[2];
	int pid;
	int master_fd;
	int slave_fd;
	char *pty_name;

	memset(&conf, 0, sizeof(conf));
	conf.memory = 32;

	if (argc == 1)
		usage(argv[0]);

	if (fuse_opt_parse(&args, &conf, mountlo_opts, mountlo_opt_proc) == -1)
		return 1;

	if (!conf.image) {
		fprintf(stderr, "missing image file\n");
		return 1;
	}

	if (!conf.mountpoint) {
		fprintf(stderr, "missing mountpoint\n");
		return 1;
	}

	tmp = do_malloc(strlen(conf.image) + 256);
	sprintf(tmp, "-ofsname=mountlo#%s", conf.image);
	fuse_opt_add_arg(&args, tmp);
	free(tmp);
	fd = fuse_kern_mount(conf.mountpoint, &args);
	if (fd == -1)
		return 1;

	if (fd != 102) {
		dup2(fd, 102);
		close(fd);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pip) == -1) {
		perror("socketpair");
		return 1;
	}
	if (pip[1] != 101) {
		dup2(pip[1], 101);
		close(pip[1]);
	}

	fuse_opt_add_arg(&iargs, "/bin/mount");
	fuse_opt_add_arg(&iargs, "-n");
	if (conf.debug || conf.verbose)
		fuse_opt_add_arg(&iargs, "-v");
	if (conf.type) {
		fuse_opt_add_arg(&iargs, "-t");
		fuse_opt_add_arg(&iargs, conf.type);
	}
	if (conf.kopts) {
		fuse_opt_add_arg(&iargs, "-o");
		fuse_opt_add_arg(&iargs, conf.kopts);
	}
	for (i = 1; i < args.argc; i++)
		fuse_opt_add_arg(&iargs, args.argv[i]);
	sprintf(tmp32, "/dev/ubd%u", conf.partition);
	fuse_opt_add_arg(&iargs, tmp32);
	fuse_opt_add_arg(&iargs, "/mnt");

	fuse_opt_add_opt(&iopts, "-ouse_ino");
	fuse_opt_add_opt(&iopts, "negative_timeout=999999999");
	fuse_opt_add_opt(&iopts, "entry_timeout=999999999");
	fuse_opt_add_opt(&iopts, "attr_timeout=999999999");
	if (conf.debug)
		fuse_opt_add_opt(&iopts, "debug");

	tmpi = conf.debug ? 2 : conf.verbose ? 1 : 0;
	write(pip[0], &tmpi, sizeof(tmpi));
	write(pip[0], &iargs.argc, sizeof(iargs.argc));
	for (i = 0; i < iargs.argc; i++) {
		len = strlen(iargs.argv[i]) + 1;
		write(pip[0], &len, sizeof(len));
		write(pip[0], iargs.argv[i], len);
	}
	len = strlen(iopts) + 1;
	write(pip[0], &len, sizeof(len));
	write(pip[0], iopts, len);

	fuse_opt_free_args(&args);
	fuse_opt_free_args(&iargs);
	free(iopts);

	master_fd = open("/dev/ptmx", O_RDWR);
	if(master_fd < 0) {
		perror("/dev/ptmx");
		return 1;
	}

	grantpt(master_fd);
	unlockpt(master_fd);
	pty_name = ptsname(master_fd);


	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	}
	if (pid != 0) {
		char last[6] = {0, 0, 0, 0, 0, 0};
		char buf[256];
		int res;
		close(101);
		close(102);
		for (;;) {
			struct pollfd pfds[2];
			int nfds = 0;
			struct pollfd *pipp = NULL;
			struct pollfd *masterp = NULL;

			if (pip[0] != -1) {
				pipp = &pfds[nfds++];
				pipp->fd = pip[0];
				pipp->events = POLLIN;
			}
			if (master_fd != -1) {
				masterp = &pfds[nfds++];
				masterp->fd = master_fd;
				masterp->events = POLLIN;
			}

			res = poll(pfds, nfds, -1);
			if (res == -1) {
				perror("poll");
				goto error_unmount;
			}

			nfds = 0;
			if (pipp && pipp->revents) {
				res = read(pip[0], buf, sizeof(buf));
				if (res == -1) {
					perror("read from control socket");
					goto error_unmount;
				}
				if (res == 0) {
					if (memcmp(last, "\nA-OK\n", sizeof(last)) == 0) {
						if (masterp == NULL)
							return 0;

						pid = fork();
						if (pid == -1) {
							perror("fork");
							goto error_unmount;
						}
						if (pid != 0)
							return 0;

						close(pip[0]);
						pip[0] = -1;
						setsid();
						close(0);
						close(1);
						close(2);
						open("/dev/null", O_RDWR);
						open("/dev/null", O_RDWR);
						open("/dev/null", O_RDWR);
						continue;
					}
					writelast(2, last, sizeof(last));
					goto error_unmount;
				}
				if (res < (int) sizeof(last)) {
					writelast(2, last, res);
					memmove(last, last + res, sizeof(last) - res);
					memcpy(last + sizeof(last) - res, buf, res);
				} else {
					writelast(2, last, sizeof(last));
					write(2, buf, res - sizeof(last));
					memcpy(last, buf + res - sizeof(last), sizeof(last));
				}
			}
			if (masterp && masterp->revents) {
				res = read(master_fd, buf, sizeof(buf));
				if (res <= 0) {
					close(master_fd);
					master_fd = -1;
					if (pipp == NULL)
						return 0;
				}

				if (conf.debug)
					write(2, buf, res);
			}

		}
	}
	/* child */
	close(pip[0]);

	slave_fd = open(pty_name, O_RDWR);
	if (slave_fd == -1) {
		perror(pty_name);
		goto error_unmount;
	}

	setsid();
	dup2(slave_fd, 0);
	dup2(slave_fd, 1);
	dup2(slave_fd, 2);

	close(master_fd);

#if 0
	if (!conf.debug) {
		setsid();
		close(0);
		close(1);
		close(2);
		open("/dev/null", O_RDWR);
		open("/dev/null", O_RDWR);
		open("/dev/null", O_RDWR);
	}
#endif
	fuse_opt_add_arg(&umlargs, argv[0]);
	tmp = do_malloc(strlen(conf.image) + 32);
	sprintf(tmp, "ubd0=%s", conf.image);
	fuse_opt_add_arg(&umlargs, tmp);
	free(tmp);
	sprintf(tmp32, "mem=%uM", conf.memory);
	fuse_opt_add_arg(&umlargs, tmp32);
	fuse_opt_add_arg(&umlargs, "root=/dev/null");
	fuse_opt_add_arg(&umlargs, "rdinit=/init");

	return uml_main(umlargs.argc, umlargs.argv, envp);

error_unmount:
	fuse_kern_unmount(conf.mountpoint, fd);
	return 1;
}

int main(int argc, char **argv, char **envp)
{
	return mountlo_main(argc, argv, envp);
}
