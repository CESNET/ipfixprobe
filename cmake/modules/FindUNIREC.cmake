# Find the unirec includes and library
#
# This module defines the following IMPORTED targets:
#
#  unirec::unirec          - The "unirec" library, if found.
#
# This module will set the following variables in your project:
#
#  UNIREC_INCLUDE_DIRS - where to find <unirec/unirec.h>, etc.
#  UNIREC_LIBRARIES    - List of libraries when using unirec.
#  UNIREC_FOUND        - True if the unirec has been found.

# Use pkg-config (if available) to get the library directories and then use
# these values as hints for find_path() and find_library() functions.
find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(PC_UNIREC QUIET UNIREC)
endif()

find_path(
	UNIREC_INCLUDE_DIR unirec/unirec.h
	HINTS ${PC_UNIREC_INCLUDEDIR} ${PC_UNIREC_INCLUDE_DIRS}
	PATH_SUFFIXES include
)

find_library(
	UNIREC_LIBRARY NAMES unirec libunirec
	HINTS ${PC_UNIREC_LIBDIR} ${PC_UNIREC_LIBRARY_DIRS}
	PATH_SUFFIXES lib lib64
)

if (PC_UNIREC_VERSION)
	# Version extracted from pkg-config
	set(UNIREC_VERSION_STRING ${PC_UNIREC_VERSION})
endif()

# Handle find_package() arguments (i.e. QUIETLY and REQUIRED) and set
# UNIREC_FOUND to TRUE if all listed variables are filled.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
	UNIREC
	REQUIRED_VARS UNIREC_LIBRARY UNIREC_INCLUDE_DIR
	VERSION_VAR UNIREC_VERSION_STRING
)

set(UNIREC_INCLUDE_DIRS ${UNIREC_INCLUDE_DIR})
set(UNIREC_LIBRARIES ${UNIREC_LIBRARY})
mark_as_advanced(UNIREC_INCLUDE_DIR UNIREC_LIBRARY)

if (UNIREC_FOUND)
	# Create imported library with all dependencies
	if (NOT TARGET unirec::unirec AND EXISTS "${UNIREC_LIBRARIES}")
		add_library(unirec::unirec UNKNOWN IMPORTED)
		set_target_properties(unirec::unirec PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			IMPORTED_LOCATION "${UNIREC_LIBRARIES}"
			INTERFACE_INCLUDE_DIRECTORIES "${UNIREC_INCLUDE_DIRS}")
	endif()
endif()
