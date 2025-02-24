# Find the nfb-framework includes and library
#
# This module defines the following IMPORTED targets:
#
#  nfb::nfb          - The "nfb" library, if found.
#
# This module will set the following variables in your project:
#
#  NFB_INCLUDE_DIRS - where to find <nfb/nfb.h>, etc.
#  NFB_LIBRARIES    - List of libraries when using nfb-framework.
#  NFB_FOUND        - True if the framework has been found.

# Use pkg-config (if available) to get the library directories and then use
# these values as hints for find_path() and find_library() functions.
find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(PC_NFB QUIET nfb-framework)
endif()

find_path(
	NFB_INCLUDE_DIR nfb/nfb.h
	HINTS ${PC_NFB_INCLUDEDIR} ${PC_NFB_INCLUDE_DIRS}
	PATH_SUFFIXES include
)

find_library(
	NFB_LIBRARY NAMES nfb libnfb
	HINTS ${PC_NFB_LIBDIR} ${PC_NFB_LIBRARY_DIRS}
	PATH_SUFFIXES lib lib64
)

if (PC_NFB_VERSION)
	# Version extracted from pkg-config
	set(NFB_VERSION_STRING ${PC_NFB_VERSION})
endif()

# Handle find_package() arguments (i.e. QUIETLY and REQUIRED) and set
# NFB_FOUND to TRUE if all listed variables are filled.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
	NFB
	REQUIRED_VARS NFB_LIBRARY NFB_INCLUDE_DIR
	VERSION_VAR NFB_VERSION_STRING
)

set(NFB_INCLUDE_DIRS ${NFB_INCLUDE_DIR})
set(NFB_LIBRARIES ${NFB_LIBRARY})
mark_as_advanced(NFB_INCLUDE_DIR NFB_LIBRARY)

if (NFB_FOUND)
	# Create imported library with all dependencies
	if (NOT TARGET nfb::nfb AND EXISTS "${NFB_LIBRARIES}")
		add_library(nfb::nfb UNKNOWN IMPORTED)
		set_target_properties(nfb::nfb PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			IMPORTED_LOCATION "${NFB_LIBRARIES}"
			INTERFACE_INCLUDE_DIRECTORIES "${NFB_INCLUDE_DIRS}")
	endif()
endif()
