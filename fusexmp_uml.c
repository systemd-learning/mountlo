/*
    mountlo: userspace loopback mount
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#define FUSE_USE_VERSION 25
#define _GNU_SOURCE

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/klog.h>
#include <sys/reboot.h>

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;

    res = lstat(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_fgetattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi)
{
    int res;

    (void) path;

    res = fstat(fi->fh, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_access(const char *path, int mask)
{
    int res;

    res = access(path, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

static int xmp_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp = opendir(path);
    if (dp == NULL)
        return -errno;

    fi->fh = (unsigned long) dp;
    return 0;
}

static inline DIR *get_dirp(struct fuse_file_info *fi)
{
    return (DIR *) (uintptr_t) fi->fh;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DIR *dp = get_dirp(fi);
    struct dirent *de;

    (void) path;
    seekdir(dp, offset);
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, de->d_off))
            break;
    }

    return 0;
}

static int xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp = get_dirp(fi);
    (void) path;
    closedir(dp);
    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;

    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;

    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    int res;

    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    int res;

    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_ftruncate(const char *path, off_t size,
                         struct fuse_file_info *fi)
{
    int res;

    (void) path;

    res = ftruncate(fi->fh, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_utime(const char *path, struct utimbuf *buf)
{
    int res;

    res = utime(path, buf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_open_common(const char *path, mode_t mode,
                           struct fuse_file_info *fi)
{
    int fd;

    fd = open(path, fi->flags, mode);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
#if defined(FUSE_VERSION) && FUSE_VERSION >= FUSE_MAKE_VERSION(2,4)
    fi->keep_cache = 1;
#endif
    return 0;
}

#define xmp_create xmp_open_common

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    return xmp_open_common(path, 0, fi);
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    res = statvfs(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_flush(const char *path, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    /* This is called from every close on an open file, so call the
       close on the underlying filesystem.  But since flush may be
       called multiple times for an open file, this must not really
       close the file.  This is important if used on a network
       filesystem like NFS which flush the data/metadata on close() */
    res = close(dup(fi->fh));
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    close(fi->fh);

    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
    int res;
    (void) path;

    if (isdatasync)
        res = fdatasync(fi->fh);
    else
        res = fsync(fi->fh);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
    int res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
                    size_t size)
{
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}

static struct fuse_operations xmp_oper = {
    .getattr	= xmp_getattr,
    .fgetattr	= xmp_fgetattr,
    .access	= xmp_access,
    .readlink	= xmp_readlink,
    .opendir	= xmp_opendir,
    .readdir	= xmp_readdir,
    .releasedir	= xmp_releasedir,
    .mknod	= xmp_mknod,
    .mkdir	= xmp_mkdir,
    .symlink	= xmp_symlink,
    .unlink	= xmp_unlink,
    .rmdir	= xmp_rmdir,
    .rename	= xmp_rename,
    .link	= xmp_link,
    .chmod	= xmp_chmod,
    .chown	= xmp_chown,
    .truncate	= xmp_truncate,
    .ftruncate	= xmp_ftruncate,
    .utime	= xmp_utime,
    .create	= xmp_create,
    .open	= xmp_open,
    .read	= xmp_read,
    .write	= xmp_write,
    .statfs	= xmp_statfs,
    .flush	= xmp_flush,
    .release	= xmp_release,
    .fsync	= xmp_fsync,
    .setxattr	= xmp_setxattr,
    .getxattr	= xmp_getxattr,
    .listxattr	= xmp_listxattr,
    .removexattr= xmp_removexattr,
};

static void do_read(int fd, void *buf, size_t len)
{
    while (len) {
        int res = read(fd, buf, len);
        if (res == -1) {
            perror("read from control socket");
            exit(1);
        }
        if (res == 0) {
            fprintf(stderr, "EOF on control socket");
            exit(1);
        }
        buf += res;
        len -= res;
    }
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

static void log_dmesg(void)
{
    int i;
    int lastc;
    char buf[16392];
    int n = klogctl(3, buf, sizeof(buf));
    if (n <= 0)
        return;

    printf("--- kernel messages:\n");
    lastc = '\n';
    for (i = 0; i < n; i++) {
        if ((i == 0 || buf[i - 1] == '\n') && buf[i] == '<') {
            i++;
            while (buf[i] >= '0' && buf[i] <= '9')
                i++;
            if (buf[i] == '>')
                i++;
        }
        lastc = buf[i];
        putchar(lastc);
    }
    if (lastc != '\n')
        putchar('\n');
    fflush(stdout);
}

static void halt_uml(void)
{
    reboot(RB_HALT_SYSTEM);
}

int main(void)
{
    struct fuse *fuse;
    int res;
    int res2;
    int ctl_fd;
    int fd;
    const char *fusedev = "/dev/fuseserv";
    char *fuseopts;
    unsigned mountopts_num;
    char **mountopts;
    unsigned i;
    unsigned fuseopts_len;
    int debug;
    int pid;
    int status;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

    atexit(halt_uml);
    umask(0);
    ctl_fd = open(fusedev, O_RDWR);
    if (ctl_fd == -1) {
        perror(fusedev);
        return 1;
    }
    do_read(ctl_fd, &debug, sizeof(debug));
    if (debug < 2) {
        dup2(ctl_fd, 1);
        dup2(ctl_fd, 2);
    }
    do_read(ctl_fd, &mountopts_num, sizeof(mountopts_num));
    mountopts = do_malloc(sizeof(char *) * (mountopts_num + 1));
    for (i = 0; i < mountopts_num; i++) {
        unsigned len;
        do_read(ctl_fd, &len, sizeof(len));
        mountopts[i] = do_malloc(len);
        do_read(ctl_fd, mountopts[i], len);
    }
    mountopts[i] = NULL;
    do_read(ctl_fd, &fuseopts_len, sizeof(fuseopts_len));
    fuseopts = do_malloc(fuseopts_len);
    do_read(ctl_fd, fuseopts, fuseopts_len);
    klogctl(5, NULL, 0);
    pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }
    if (!pid) {
        execv("/bin/mount", mountopts);
        return 1;
    }
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        if (debug && WIFEXITED(status))
            fprintf(stderr, "mount exit status: %i\n", WEXITSTATUS(status));

        if (WIFSIGNALED(status))
            fprintf(stderr, "mount killed with signal %i\n", WTERMSIG(status));
        else if (!WIFEXITED(status))
            fprintf(stderr, "mount died\n");

        if (debug < 2)
            log_dmesg();

        return 1;
    }
    if (debug == 1)
        log_dmesg();

    write(ctl_fd, "\nA-OK\n", 6);
    if (debug < 2) {
        close(1);
        close(2);
        close(ctl_fd);
    }

    fd = open(fusedev, O_RDWR);
    if (fd == -1) {
        perror(fusedev);
        return 1;
    }
    fuse_opt_add_arg(&args, "");
    fuse_opt_add_arg(&args, fuseopts);
    fuse = fuse_new(fd, &args, &xmp_oper, sizeof(xmp_oper));
    if (fuse == NULL)
        return 1;

    chdir("/");
    chroot("/mnt");
    res = fuse_loop(fuse);
    fuse_destroy(fuse);
    close(fd);
    sync();
    res2 = umount2("./mnt", 0);
    if (res2 == -1) {
        perror("umount");
        if (!res)
            res = 1;
    }
    return res;
}
