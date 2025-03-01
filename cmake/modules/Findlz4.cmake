# Find lz4
# Once done this will define
#
#  LZ4_FOUND - system has liblz4
#  lz4::lz4 - cmake target 

find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(PC_LZ4 QUIET lz4-devel)
endif()

find_path (LZ4_INCLUDE_DIR 
  NAMES lz4.h
  HINTS ${LZ4_ROOT} ${PC_LZ4_INCLUDEDIR} ${PC_LZ4_INCLUDE_DIRS}
  PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR}
)

find_library (LZ4_LIBRARY 
  NAMES lz4
  HINTS ${LZ4_ROOT} ${PC_LZ4_LIBDIR} ${PC_LZ4_LIBRARY_DIRS}
  PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR}  
)

mark_as_advanced (LZ4_INCLUDE_DIR LZ4_LIBRARY)

include (FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set Unwind_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args (lz4
  REQUIRED_VARS LZ4_INCLUDE_DIR LZ4_LIBRARY
)

if (NOT TARGET lz4::lz4)
  add_library(lz4::lz4 STATIC IMPORTED)
  set_target_properties(lz4::lz4 PROPERTIES
    IMPORTED_LOCATION "${LZ4_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LZ4_INCLUDE_DIR}")
  target_compile_definitions(lz4::lz4 INTERFACE LZ4_FOUND)
else()
  message(CRITICAL "lz4 was not found")
  add_library(lz4::lz4 INTERFACE IMPORTED)
endif()

unset(LZ4_INCLUDE_DIR)
unset(LZ4_LIBRARY)