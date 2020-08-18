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
  PKG_CHECK_MODULES([libtrap], [libtrap], [HAVE_TRAPLIB="yes"])
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

