dnl @synopsis AX_LIBTRAP_CHECK
dnl
dnl This macro test if libtrap is installed or if it is
dnl in parent directory.  It sets CFLAGS, CXXFLAGS, LDFLAGS,
dnl LIBS if libtrap is found.  Otherwise, error is returned.
dnl
dnl @category InstalledPackages
dnl @author Tomas Cejka <cejkat@cesnet.cz>
dnl @version 2015-08-02
dnl @license BSD

AC_DEFUN([AX_LIBTRAP_CHECK], [
  AC_CHECK_HEADERS([getopt.h])
  AC_CHECK_FUNCS([getopt_long getopt])

  if test "x$ac_cv_func_getopt_long" = xyes; then
    AC_DEFINE_UNQUOTED([TRAP_GETOPT(argc, argv, optstr, longopts)],
      [getopt_long(argc, argv, optstr, longopts, NULL)],
      [Trap getopt macro. Argc and argv are number and values of arguments, optstr is a string containing legitimate option characters, longopts is the array of option structures (unused for on system without getopt_long())])
  elif test "x$ac_cv_func_getopt" = xyes; then
    AC_DEFINE_UNQUOTED([TRAP_GETOPT(argc, argv, optstr, longopts)],
    [getopt(argc, argv, optstr)],
    [Trap getopt macro. Argc and argv are number and values of arguments, optstr is a string containing legitimate option characters, longopts is the array of option structures (unused for on system without getopt_long())])
  else
    AC_MSG_ERROR([getopt() was not found, module depend on it...])
  fi

  TRAPLIB=""
  if test "${repobuild}" = "false"; then
    PKG_CHECK_MODULES([libtrap], [libtrap], [HAVE_TRAPLIB="yes"])
  fi
  if test "${HAVE_TRAPLIB}" != "yes"; then
    # repobuild
    AC_MSG_CHECKING([for libtrap in parent directory])
    if test -d "$srcdir/../libtrap"; then
      TRAPINC='$(top_srcdir)/../libtrap/include'
      TRAPLIB='$(top_builddir)/../libtrap/src/.libs'
    elif test -d "$srcdir/../../libtrap"; then
      TRAPINC='$(top_srcdir)/../../libtrap/include'
      TRAPLIB='$(top_builddir)/../../libtrap/src/.libs'
    elif test -d "$srcdir/nemea-framework/libtrap"; then
      TRAPINC='$(top_srcdir)/nemea-framework/libtrap/include'
      TRAPLIB='$(top_builddir)/nemea-framework/libtrap/src/.libs'
    elif test -d "$srcdir/../nemea-framework/libtrap"; then
      TRAPINC='$(top_srcdir)/../nemea-framework/libtrap/include'
      TRAPLIB='$(top_builddir)/../nemea-framework/libtrap/src/.libs'
    fi
    if test -n "$TRAPLIB"; then
      libtrap_LDFLAGS="-L${TRAPLIB}"
      libtrap_CFLAGS="-I${TRAPINC}"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
      TRAPLIB=""
      PKG_CHECK_MODULES([libtrap], [libtrap], [HAVE_TRAPLIB="yes"])
    fi
  fi
  if test -n "$TRAPLIB"; then
    CPPFLAGS="-I${TRAPINC} $CPPFLAGS"
    LIBS="-L${TRAPLIB} $LIBS"
  elif test "x$HAVE_TRAPLIB" = "xyes"; then
    CPPFLAGS="${libtrap_CFLAGS} $CPPFLAGS"
    LIBS="${libtrap_LIBS} $LIBS"
  else
    AC_MSG_ERROR([Libtrap was not found.])
  fi
  nemeasupdir=${datarootdir}/nemea-supervisor
  AC_SUBST(nemeasupdir)
  AC_PATH_PROG([TRAP2MAN], [trap2man.sh], [], [/usr/bin/nemea$PATH_SEPARATOR$PATH$PATH_SEPARATOR$PWD/../nemea-framework/libtrap/tools])
  AM_CONDITIONAL([HAVE_TRAP2MAN], [test -x "$TRAP2MAN"])
])

