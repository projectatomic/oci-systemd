AC_INIT([OCI Systemd Hook], 0.1.14)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])
AC_PROG_CC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])
PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.0.0])
PKG_CHECK_MODULES([LIBMOUNT], [mount >= 2.23.0])

AC_MSG_CHECKING([whether to disable argument checking])
AC_ARG_ENABLE([args], AS_HELP_STRING([--disable-args], [disable checking that cmd args are either init/systemd]))
AS_IF([test "x$enable_args" != "xno"], [AC_DEFINE([ARGS_CHECK], [1], [enable checking arguments])])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
