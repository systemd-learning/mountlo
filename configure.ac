AC_INIT(mountlo, 0.6)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_PROG_CC
if test "$ac_env_CFLAGS_set" != set; then
   CFLAGS="-Wall -W -O2"
fi
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
PKG_CHECK_MODULES(FUSE, [fuse >= 2.5])
AC_OUTPUT

