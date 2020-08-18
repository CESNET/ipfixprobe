#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ipfixprobe], [2.16.0], [nemea@cesnet.cz])

AC_CONFIG_SRCDIR([xxhash.h])
AC_CONFIG_HEADERS([config.h])

RELEASE=1
AC_SUBST(RELEASE)
USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`
AC_SUBST(USERNAME)
AC_SUBST(USERMAIL)
AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects])
AM_SILENT_RULES([yes])
RPM_REQUIRES=
RPM_BUILDREQ=

AC_CONFIG_MACRO_DIR([m4])
# Must be checked before default -g -O2 is set:
AC_ARG_ENABLE([debug],
        AC_HELP_STRING([--enable-debug],
        [Enable build with debug symbols and without optimizations.]),
        [if test "$enableval" = "yes"; then
              CXXFLAGS="-Wall -g -O0 $CXXFLAGS"
        fi], [CXXFLAGS="-Wall -g -O3 $CXXFLAGS"
              CPPFLAGS="-DNDEBUG=1 $CPPFLAGS"])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

LT_INIT()

# Checks for programs.
AC_PROG_CXX
AC_PROG_CPP
# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
AC_CHECK_PROG(DEBUILD, debuild, debuild, [""])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AX_C_BIGENDIAN_CROSS

AC_ARG_WITH([ndp],
        AC_HELP_STRING([--with-ndp],[Compile flow_meter with ndp library.]),
        [
      if test "$withval" = "yes"; then
         withndp="yes"
      else
         withndp="no"
      fi
        ], [withndp="no"]
)

if test x${withndp} = xyes; then
        AC_CHECK_HEADER(nfb/nfb.h, AC_CHECK_LIB(nfb, nfb_open, [libnfb=yes],
          [AC_MSG_WARN([libnfb not found. The flow_meter module will not be compiled.])]
        ), AC_MSG_WARN([nfb/nfb.h not found. The flow_meter module will not be compiled.]))
fi

AM_CONDITIONAL(HAVE_NDP,  test x${libnfb} = xyes && test x${withndp} = xyes)
if [[ -z "$HAVE_NDP_TRUE" ]]; then
AC_DEFINE([HAVE_NDP], [1], [Define to 1 if the ndp is available])
RPM_REQUIRES+=" netcope-common"
RPM_BUILDREQ+=" netcope-common-devel"
fi

if test x${withndp} = xno; then
   AC_CHECK_HEADER(pcap.h,
              AC_CHECK_LIB(pcap, pcap_open_live, [libpcap=yes], AC_MSG_WARN([libpcap not found. The flow_meter module will not be compiled.])), AC_MSG_WARN([pcap.h not found. The flow_meter module will not be compiled.]))

   AM_CONDITIONAL(HAVE_LIBPCAP, test x${libpcap} = xyes)
   if [[ -z "$HAVE_LIBPCAP_TRUE" ]]; then
   RPM_REQUIRES+=" libpcap"
   RPM_BUILDREQ+=" libpcap-devel"
   fi
else
   AM_CONDITIONAL(HAVE_LIBPCAP, false)
fi

AC_ARG_WITH([nemea],
        AC_HELP_STRING([--with-nemea],[Compile with NEMEA framework (nemea.liberouter.org).]),
        [
      if test "$withval" = "yes"; then
         withnemea="yes"
         AX_LIBTRAP_CHECK()
         AX_UNIREC_CHECK()
      else
         withnemea="no"
      fi
        ], [withnemea="no"]
)

AM_CONDITIONAL(WITH_NEMEA,  test x${withnemea} = xyes)

if [[ -z "$WITH_NEMEA_TRUE" ]]; then
AC_DEFINE([WITH_NEMEA], [1], [Define to 1 if the NEMEA is available])
RPM_REQUIRES+=" libtrap"
RPM_BUILDREQ+=" libtrap-devel unirec"
else
CPPFLAGS="-DDISABLE_UNIREC $CPPFLAGS"
fi

AM_CONDITIONAL(COMPILE_FLOWMETER,  test x${libpcap} = xyes || test x${libnfb} = xyes)

AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

AM_CONDITIONAL(MAKE_DEB, test x$DEBUILD != x)

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset socket strchr strerror strncasecmp strstr strtol strtoul strtoull])

AC_CONFIG_FILES([Makefile
                 nfbCInterface/Makefile
                 tests/Makefile])

#AC_CONFIG_SUBDIRS([nfbCInterface])

AC_OUTPUT