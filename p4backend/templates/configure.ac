AC_INIT([ipfixprobe], [1.0])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects])
AM_SILENT_RULES([yes])
AC_ARG_ENABLE([debug],
        AC_HELP_STRING([--enable-debug],
        [Enable build with debug symbols and without optimizations.]),
        [if test "$enableval" = "yes"; then
                CFLAGS="-Wall -g -O0 $CFLAGS"
                CXXFLAGS="-Wall -g -O0 $CXXFLAGS"
        fi], [CFLAGS="-Wall -O3 $CFLAGS"
              CXXFLAGS="-Wall -O3 $CXXFLAGS"
              CPPFLAGS="-DNDEBUG=1 $CPPFLAGS"])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")
LT_INIT()

AC_PREREQ([2.69])
AC_CONFIG_SRCDIR([ipfix.c])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_next_ex], [], [AC_MSG_ERROR([libpcap not found])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netdb.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset socket strerror strstr strtoull])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
