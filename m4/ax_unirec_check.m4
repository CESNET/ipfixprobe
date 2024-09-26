dnl @synopsis AX_UNIREC_CHECK
dnl
dnl This macro test if unirec is installed or if it is
dnl in parent directory.  It sets CFLAGS, CXXFLAGS, LDFLAGS,
dnl LIBS if libtrap is found.  Otherwise, error is returned.
dnl This macro depends on $repobuild, if it is "true",
dnl UniRec processor will be located in parent directory,
dnl otherwise in /usr/bin/nemea.
dnl
dnl @category InstalledPackages
dnl @author Tomas Cejka <cejkat@cesnet.cz>
dnl @version 2015-08-02
dnl @license BSD

AC_DEFUN([AX_UNIREC_CHECK_INTERNAL_PARENT], [
  AC_MSG_CHECKING([for unirec in parent directory])
  # Check for unirec as a superproject.
  if test -d "$srcdir/../unirec"; then
    UNIRECINC='$(top_srcdir)/../'
    UNIRECLIB='$(top_builddir)/../unirec/.libs/'
  elif test -d "$srcdir/../../unirec"; then
    UNIRECINC='$(top_srcdir)/../../'
    UNIRECLIB='$(top_builddir)/../../unirec/.libs/'
  elif test -d "$srcdir/nemea-framework/unirec"; then
    UNIRECINC='$(top_srcdir)/nemea-framework/'
    UNIRECLIB='$(top_builddir)/nemea-framework/unirec/.libs/'
  elif test -d "$srcdir/../nemea-framework/unirec"; then
    UNIRECINC='$(top_srcdir)/../nemea-framework/'
    UNIRECLIB='$(top_builddir)/../nemea-framework/unirec/.libs/'
  fi

  # AC_SUBST command line variables from UNIRECLIB and UNIRECINC.
  if test -n "$UNIRECLIB"; then
    AC_SUBST([UNIREC_LTLIB], ["$TRAPLIB/libtrap.la"])
    AC_SUBST([UNIREC_INCLUDE], ["-I$TRAPINC"])
    LIBS="-L$UNIRECLIB $LIBS"
    CFLAGS="-I$UNIRECINC $CFLAGS"
    CXXFLAGS="-I$UNIRECINC $CXXFLAGS"
    AC_MSG_RESULT([yes])
  else
    AC_CHECK_HEADERS(unirec/unirec.h unirec/inline.h unirec/ipaddr_cpp.h unirec/ipaddr.h unirec/links.h unirec/ur_time.h unirec/ur_values.h,
      [], [AC_MSG_RESULT([no])])
    AC_CHECK_LIB([unirec], ur_create_template, [UNIRECLIB=" "])
  fi
])

AC_DEFUN([AX_UNIREC_CHECK], [
  # UniRec processor
  if test "$repobuild" = "true"; then
  AC_PATH_PROG(UNIRECPROC, ur_processor.sh, [],
      [$PWD/nemea-framework/unirec$PATH_SEPARATOR$PWD/../nemea-framework/unirec$PATH_SEPARATOR$PWD/../unirec$PATH_SEPARATOR$srcdir/../nemea-framework/unirec$PATH_SEPARATOR$top_srcdir/nemea-framework/unirec$PATH_SEPARATOR$PATH$PATH_SEPARATOR/usr/bin/nemea/])
  else
  AC_PATH_PROG(UNIRECPROC, ur_processor.sh, [],
      [/usr/bin/nemea/$PATH_SEPARATOR$PATH])
  fi

  if test -z "$UNIRECPROC"; then
      AC_MSG_ERROR([UniRec processor was not found. Add path to "ur_processor.sh" into PATH or install UniRec."])
  fi

  AC_SUBST(UNIRECPROC)

  UNIRECLIB=""
  if test "$repobuild" = "true"; then
    AX_UNIREC_CHECK_INTERNAL_PARENT()
  else
    PKG_CHECK_MODULES([unirec], [unirec], [UNIRECLIB="yes"], [
      AX_UNIREC_CHECK_INTERNAL_PARENT()
    ])
  fi
  if test -n "$UNIRECLIB"; then
    LDFLAGS="$unirec_LDFLAGS $LDFLAGS"
    LIBS="$unirec_LIBS $LIBS"
    CFLAGS="$unirec_CFLAGS $CFLAGS"
    CXXFLAGS="$unirec_CFLAGS $CXXFLAGS"
  else
    AC_MSG_ERROR([unirec was not found.])
  fi
])

