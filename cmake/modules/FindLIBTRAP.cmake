# Find the libtrap includes and library
#
# This module defines the following IMPORTED targets:
#
#  trap::trap          - The "trap" library, if found.
#
# This module will set the following variables in your project:
#
#  LIBTRAP_INCLUDE_DIRS - where to find <libtrap/trap.h>, etc.
#  LIBTRAP_LIBRARIES    - List of libraries when using libtrap.
#  LIBTRAP_FOUND        - True if the libtrap has been found.

# Use pkg-config (if available) to get the library directories and then use
# these values as hints for find_path() and find_library() functions.
find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(PC_LIBTRAP QUIET libtrap)
endif()

find_path(
	LIBTRAP_INCLUDE_DIR libtrap/trap.h
	HINTS ${PC_LIBTRAP_INCLUDEDIR} ${PC_LIBTRAP_INCLUDE_DIRS}
	PATH_SUFFIXES include
)

find_library(
	LIBTRAP_LIBRARY NAMES trap libtrap
	HINTS ${PC_LIBTRAP_LIBDIR} ${PC_LIBTRAP_LIBRARY_DIRS}
	PATH_SUFFIXES lib lib64
)

if (PC_LIBTRAP_VERSION)
	# Version extracted from pkg-config
	set(LIBTRAP_VERSION_STRING ${PC_LIBTRAP_VERSION})
endif()

# Handle find_package() arguments (i.e. QUIETLY and REQUIRED) and set
# LIBTRAP_FOUND to TRUE if all listed variables are filled.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
	LIBTRAP
	REQUIRED_VARS LIBTRAP_LIBRARY LIBTRAP_INCLUDE_DIR
	VERSION_VAR LIBTRAP_VERSION_STRING
)

set(LIBTRAP_INCLUDE_DIRS ${LIBTRAP_INCLUDE_DIR})
set(LIBTRAP_LIBRARIES ${LIBTRAP_LIBRARY})
mark_as_advanced(LIBTRAP_INCLUDE_DIR LIBTRAP_LIBRARY)

if (LIBTRAP_FOUND)
	# Create imported library with all dependencies
	if (NOT TARGET trap::trap AND EXISTS "${LIBTRAP_LIBRARIES}")
		add_library(trap::trap UNKNOWN IMPORTED)
		set_target_properties(trap::trap PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			IMPORTED_LOCATION "${LIBTRAP_LIBRARIES}"
			INTERFACE_INCLUDE_DIRECTORIES "${LIBTRAP_INCLUDE_DIRS}")
	endif()
endif()
