#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ipfixprobe], [4.6.0], [nemea@cesnet.cz])

AC_CONFIG_SRCDIR([main.cpp])
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
              CFLAGS="-Wall -g -O0 $CFLAGS"
         else
              CXXFLAGS="-Wall -g -O3 $CXXFLAGS"
              CFLAGS="-Wall -g -O3 $CFLAGS"
        fi], [CXXFLAGS="-Wall -g -O3 $CXXFLAGS"
              CPPFLAGS="-DNDEBUG=1 $CPPFLAGS"
              CFLAGS="-Wall -g -O3"])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

AC_ARG_ENABLE([coprrpm],
        AC_HELP_STRING([--enable-coprrpm],
        [Enable NEMEA as a default dependency of RPM. This option simplifies copr build without parameters.]),
        [if test "$enableval" = "yes"; then
                COPRRPM=yes
        fi], [COPRRPM=no])
AC_SUBST(COPRRPM)

LT_INIT()

bashcompldir=${sysconfdir}/bash_completion.d
AC_SUBST(bashcompldir)


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
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AX_C_BIGENDIAN_CROSS


AC_ARG_WITH([defaultsocketdir],
   [AS_HELP_STRING([--with-defaultsocketdir=DIR], [Directory for UNIX&service IFCs [/tmp], for production set it to e.g. /var/run/ipfixprobe.])],
   [],
   [with_defaultsocketdir=/tmp])

AC_SUBST([defaultsocketdir], [$with_defaultsocketdir])
AC_DEFINE_DIR([DEFAULTSOCKETDIR], [defaultsocketdir], [Default path to socket directory])

AC_CHECK_LIB(atomic, __atomic_store, [libatomic=yes], AC_MSG_ERROR([libatomic not found]))

### gtest
AC_ARG_WITH([gtest],
        AC_HELP_STRING([--with-gtest],[Compile ipfixprobe with gtest framework]),
        [
      if test "$withval" = "yes"; then
         withgtest="yes"
      else
         withgtest="no"
      fi
        ], [withgtest="no"]
)

if test x${withgtest} = xyes; then
   GTEST_HEADER="googletest/googletest/include/gtest/gtest.h"
   AC_MSG_CHECKING(for googletest submodule)
   AM_CONDITIONAL([HAVE_GOOGLETEST], [test -f $GTEST_HEADER])
   AS_IF([test -f googletest/googletest/include/gtest/gtest.h],
      [AC_DEFINE(HAVE_GOOGLETEST, 1, [Define to 1 if the googletest submodule is available]) AC_MSG_RESULT(yes)],
      [AC_MSG_ERROR([
   The googletest submodule is not present, so such tests are omitted. To prevent skipping use command:
   git clone --recurse-submodules <this_repository> or
   git clone https://github.com/google/googletest.git])]
   )
else
AM_CONDITIONAL([HAVE_GOOGLETEST], [test])
fi


### openssl
AC_ARG_ENABLE([legacy-ssl],
       AC_HELP_STRING([--enable-legacy-ssl],[Compile ipfixprobe on centos7.]),
       [
       if test "$enableval" = "yes"; then
          legacyssl="yes"
       else
          legacyssl="no"
       fi
         ], [
          legacyssl="no"
         ]
)
### openssl


AC_ARG_WITH([quic],
        AC_HELP_STRING([--without-quic],[Compile ipfixprobe without quic plugin (which have dependency on openssl-devel)]),
        [
      if test "$withval" = "yes"; then
         withquic="yes"
      else
         withquic="no"
      fi
        ], [withquic="yes"]
)

if test x${withquic} = xyes; then
   if test x"${legacyssl}" = xyes; then
      LIBS="-l:libcrypto.so.1.1 $LIBS"
      CXXFLAGS="-I/usr/include/openssl11/ $CXXFLAGS"
      RPM_BUILDREQ+=" openssl11-devel"
      RPM_REQUIRES+=" openssl11"
      AC_CHECK_FILE(/usr/include/openssl11/openssl/kdf.h, ,
      AC_MSG_ERROR([openssl/kdf.h not found. Try installing at least version 1.1 of openssl-devel]))
   else
      RPM_REQUIRES+=" openssl"
      RPM_BUILDREQ+=" openssl-devel"
      AC_CHECK_LIB(crypto, EVP_PKEY_CTX_new_id, [],
     [AC_MSG_ERROR([libcrypto not found. Try installing at least version 1.1 of openssl-devel])])
   fi
fi

AM_CONDITIONAL(WITH_QUIC,  test x${withquic} = xyes)
if [[ -z "$WITH_QUIC_TRUE" ]]; then
   AC_DEFINE([WITH_QUIC], [1], [Define to 1 if compile with quic plugin])
fi


AM_CONDITIONAL(OS_CYGWIN, test x${host_os} = xcygwin)

AC_ARG_WITH([raw],
        AC_HELP_STRING([--without-raw],[Compile ipfixprobe with raw plugin for capturing using raw sockets]),
        [
      if test "$withval" = "yes"; then
         if [[ -z "$OS_CYGWIN_TRUE" ]]; then
            AC_MSG_ERROR(["raw plugin is not supported on cygwin"])
         fi
         withraw="yes"
      else
         withraw="no"
      fi
        ], [withraw="yes"]
)

if [[ -z "$OS_CYGWIN_TRUE" ]] && test "$withraw" = "yes"; then
   AC_MSG_WARN(["raw plugin is not supported on cygwin"])
   withraw="no"
fi

AM_CONDITIONAL(WITH_RAW,  test x${withraw} = xyes)
if [[ -z "$WITH_RAW_TRUE" ]]; then
   AC_CHECK_HEADERS([linux/if_packet.h net/ethernet.h net/if.h ifaddrs.h])
   AC_CHECK_TYPES([struct tpacket3_hdr],[],AC_MSG_ERROR(["TPACKET_V3 required for raw sockets plugin. Upgrade kernel to version 3.19 at least"]), [#include <linux/if_packet.h>])
   AC_DEFINE([WITH_RAW], [1], [Define to 1 if compile with raw plugin])
fi


AC_ARG_WITH([ndp],
        AC_HELP_STRING([--with-ndp],[Compile ipfixprobe with ndp plugin for capturing using netcope-common library]),
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
          [AC_MSG_ERROR([libnfb not found. Try installing netcope-common])]
        ), AC_MSG_ERROR([nfb/nfb.h not found. Try installing netcope-common-devel]))
fi

AM_CONDITIONAL(WITH_NDP,  test x${libnfb} = xyes && test x${withndp} = xyes)
if [[ -z "$WITH_NDP_TRUE" ]]; then
   AC_DEFINE([WITH_NDP], [1], [Define to 1 if the ndp is available])
   CPPFLAGS="$CPPFLAGS -DIPXP_FLOW_CACHE_SIZE=19 -DIPXP_FLOW_LINE_SIZE=2" # 524288 cache records, 4 record per line
   LIBS="-lnfb $LIBS"
   RPM_REQUIRES+=" netcope-common"
   RPM_BUILDREQ+=" netcope-common-devel"
fi

AC_ARG_WITH([pcap],
        AC_HELP_STRING([--with-pcap],[Compile ipfixprobe with pcap plugin for capturing using libpcap library]),
        [
      if test "$withval" = "yes"; then
         withpcap="yes"
      else
         withpcap="no"
      fi
        ], [withpcap="no"]
)

if test x${withpcap} = xyes; then
   AC_CHECK_HEADER(pcap.h,
              AC_CHECK_LIB(pcap, pcap_open_live, [libpcap=yes],
                           AC_CHECK_LIB(wpcap, pcap_open_live, [libwpcap=yes], AC_MSG_ERROR([libpcap not found. Try installing libpcap]))),
                           AC_MSG_ERROR([pcap.h not found. Try installing libpcap-devel or libwpcap-devel]))
fi

AM_CONDITIONAL(WITH_PCAP, test x${withpcap} && (test x${libpcap} = xyes || test x${libwpcap} = xyes))
if [[ -z "$WITH_PCAP_TRUE" ]]; then
   AC_DEFINE([WITH_PCAP], [1], [Define to 1 if the libpcap is available])
   if [[ -z "$WITH_PCAP_TRUE" ]]; then
      if test x${libpcap} = xyes; then
         LIBS="-lpcap $LIBS"
         RPM_REQUIRES+=" libpcap"
         RPM_BUILDREQ+=" libpcap-devel"
      else
         LIBS="-lwpcap $LIBS"
         RPM_REQUIRES+=" libwpcap"
         RPM_BUILDREQ+=" libwpcap-devel"
      fi
   fi
fi


AC_ARG_WITH([unwind],
        AC_HELP_STRING([--with-unwind],[Compile ipfixprobe with libunwind to print stack on crash]),
        [
      if test "$withval" = "yes"; then
         withunwind="yes"
      else
         withunwind="no"
      fi
        ], [withunwind="no"]
)

if test x${withunwind} = xyes; then
   AC_CHECK_HEADER(libunwind.h,
         AC_CHECK_LIB(unwind, unw_backtrace, [libunwind=yes], AC_MSG_ERROR([libunwind not found])),
         AC_MSG_ERROR([libunwind.h not found]))

   AM_CONDITIONAL(WITH_LIBUNWIND, test x${libunwind} = xyes)
   if [[ -z "$WITH_LIBUNWIND_TRUE" ]]; then
      AC_DEFINE([WITH_LIBUNWIND], [1], [Define to 1 if the libunwind is available])
      LIBS="-lunwind $LIBS"
      RPM_REQUIRES+=" libunwind"
      RPM_BUILDREQ+=" libunwind-devel"
   fi
else
   AM_CONDITIONAL(WITH_LIBUNWIND, false)
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
if test x${withnemea} = xno; then
AM_CONDITIONAL([HAVE_TRAP2MAN], [false])
fi

AM_CONDITIONAL(WITH_NEMEA,  test x${withnemea} = xyes)

if [[ -z "$WITH_NEMEA_TRUE" ]]; then
AC_DEFINE([WITH_NEMEA], [1], [Define to 1 if the NEMEA is available])
RPM_REQUIRES+=" libtrap"
RPM_BUILDREQ+=" libtrap-devel unirec"
fi

AC_ARG_WITH([osquery],
        AC_HELP_STRING([--with-osquery],[Compile with osquery framework (osquery.io).]),
        [
      if test "$withval" = "yes"; then
        withosquery="yes"
        AC_CHECK_PROG(OSQUERY, osqueryi, yes)
        AS_IF([test x${OSQUERY} != xyes], [AC_MSG_ERROR([Please install osquery before configuring.])])
      else
        withosquery="no"
      fi
        ], [withosquery="no"]
)

AM_CONDITIONAL(WITH_OSQUERY, test x${withosquery} = xyes)

if [[ -z "$WITH_OSQUERY_TRUE" ]]; then
  AC_DEFINE([WITH_OSQUERY], [1], [Define to 1 if the osquery is available])
fi


AC_ARG_WITH([dpdk],
         AS_HELP_STRING([--with-dpdk],[Compile ipfixprobe with DPDK interface support.]),
         [
            if test "$withval" = "yes"; then
               withdpdk="yes"
            else
               withdpdk="no"
            fi
         ],
         [withdpdk="no"]
)

AM_CONDITIONAL(WITH_DPDK, test x${withdpdk} = xyes)
if [[ -z "$WITH_DPDK_TRUE" ]]; then
   AC_DEFINE([WITH_DPDK], [1], [Define 1 if DPDK interface will be used])
   PKG_CHECK_MODULES([DPDK], [libdpdk])
   CFLAGS="$DPDK_CFLAGS $CFLAGS"
   CXXFLAGS="$DPDK_CFLAGS $CXXFLAGS"
   LIBS="$DPDK_LIBS $LIBS"
fi

AC_ARG_WITH([flexprobe],
         AC_HELP_STRING([--with-flexprobe], [Compile with support for flexprobe data processing plugins.]),
         [
            if test "$withval" = "yes"; then
               withflexprobe="yes"
            else
               withflexprobe="no"
            fi
         ],
         [withflexprobe="no"]
)

AM_CONDITIONAL(WITH_FLEXPROBE, test x${withflexprobe} = xyes)
if [[ -z "$WITH_FLEXPROBE_TRUE" ]]; then
   AC_DEFINE([WITH_FLEXPROBE], [1], [Define to 1 to use flexprobe plugins])
fi

AC_ARG_WITH([stem],
         AC_HELP_STRING([--with-stem], [Compile with FlexProbe StEm testing interface]),
         [
            if test "$withval" = "yes"; then
               withstem="yes"
            else
               withstem="no"
            fi
         ],
         [withstem="no"]
)

AM_CONDITIONAL(WITH_STEM, test x${withstem} = xyes)
if [[ -z "$WITH_STEM_TRUE" ]]; then
   AC_DEFINE([WITH_STEM], [1], [Define to 1 to use flexprobe testing interface])
   CFLAGS="-I/usr/local/include/Stem $CFLAGS"
   CXXFLAGS="-I/usr/local/include/Stem -std=gnu++17 -g -Wno-write-strings $CXXFLAGS"
   LIBS="-lstem $LIBS"
fi


AC_ARG_WITH([flowcachesize],
       AC_HELP_STRING([--with-flowcachesize=EXPONENT],[Set default size of flow cache, accept exponent to the power of 2 number]),
       [
       CPPFLAGS="$CPPFLAGS -DIPXP_FLOW_CACHE_SIZE=$withval"
       ]
)

AC_ARG_WITH([flowlinesize],
       AC_HELP_STRING([--with-flowlinesize=EXPONENT],[Set default size of flow line, accept exponent to the power of 2 number]),
       [
       CPPFLAGS="$CPPFLAGS -DIPXP_FLOW_LINE_SIZE=$withval"
       ]
)

AC_ARG_WITH([msects],
       AC_HELP_STRING([--with-msects],[Compile ipfix plugin with miliseconds timestamp precision output instead of microsecond precision]),
       [
       CPPFLAGS="$CPPFLAGS -DIPXP_TS_MSEC"
       ]
)


AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

AM_CONDITIONAL(MAKE_DEB, test x$DEBUILD != x)

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_STRTOD
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset socket strchr strerror strncasecmp strstr strtol strtoul strtoull])

AC_ARG_WITH([systemdsystemunitdir],
        [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],
        [],
        [with_systemdsystemunitdir=auto])

AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
def_systemdsystemunitdir=$(pkg-config --variable=systemdsystemunitdir systemd)])

AS_IF([test "x$def_systemdsystemunitdir" = "x"], [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"], [with_systemdsystemunitdir=no])],
[with_systemdsystemunitdir="$def_systemdsystemunitdir"])
#AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])],

AS_IF([test "x$with_systemdsystemunitdir" = "xno" -o "x$with_systemdsystemunitdir" = "xauto"], [with_systemdsystemunitdir=/usr/lib/systemd/system])

AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])


if [[ -z "$HAVE_GOOGLETEST_TRUE" ]]; then
# 5ec7f0c4a113e2f18ac2c6cc7df51ad6afc24081
AC_CONFIG_SUBDIRS([googletest])
fi

AC_CONFIG_FILES([Makefile
                 ipfixprobe.spec
                 ipfixprobe.bash
                 input/nfbCInterface/Makefile
                 init/Makefile
                 tests/Makefile
                 tests/functional/Makefile
                 tests/unit/Makefile])

#AC_CONFIG_SUBDIRS([nfbCInterface])

AC_OUTPUT

echo
echo
echo "------------------------------------------------------------------------"
echo "$PACKAGE $VERSION"
echo "------------------------------------------------------------------------"
echo
echo
echo "Configuration Options Summary:"
echo
echo "  ASM.(32 bit only)......: $ASM"
echo "  Static binary..........: $static"
echo
echo "Documentation............: ${build_doc}"
echo
echo "UniRec processor.........: $UNIRECPROC"
echo "trap2man.sh..............: $TRAP2MAN"
echo "Compilation..............: make (or gmake)"
echo "  CPPFLAGS...............: $CPPFLAGS"
echo "  CFLAGS.................: $CFLAGS"
echo "  CXXFLAGS...............: $CXXFLAGS"
echo "  LDFLAGS................: $LDFLAGS"
echo "  LIBS...................: $LIBS"
echo "Enforced NEMEA (for copr): $COPRRPM"
echo "FlexProbe Data Interface.: $withflexprobe"
echo "DPDK Interface...........: $withdpdk"
echo
echo "Installation.............: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix.................: $prefix"
echo
