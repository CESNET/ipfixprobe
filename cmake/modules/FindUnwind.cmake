# Find unwind library
# Once done this will define
#
#  UNWIND_FOUND - system has libunwind
#  unwind::unwind - cmake target 

find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(PC_UNWIND QUIET libunwind)
endif()

find_path (UNWIND_INCLUDE_DIR 
  NAMES unwind.h libunwind.h
  HINTS ${UNWIND_ROOT} ${PC_UNWIND_INCLUDEDIR} ${PC_UNWIND_INCLUDE_DIRS}
  PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR}
)

find_library (UNWIND_LIBRARY 
  NAMES unwind
  HINTS ${UNWIND_ROOT} ${PC_UNWIND_LIBDIR} ${PC_UNWIND_LIBRARY_DIRS}
  PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR}  
)

mark_as_advanced (UNWIND_INCLUDE_DIR UNWIND_LIBRARY)

include (FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set Unwind_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args (Unwind
  REQUIRED_VARS UNWIND_INCLUDE_DIR UNWIND_LIBRARY
)

if (UNWIND_FOUND AND NOT TARGET unwind::unwind)
  add_library(unwind::unwind STATIC IMPORTED)
  set_target_properties(unwind::unwind PROPERTIES
    IMPORTED_LOCATION "${UNWIND_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${UNWIND_INCLUDE_DIR}")
  target_compile_definitions(unwind::unwind INTERFACE UNWIND_FOUND)
else()
  message(WARNING "Notice: UNWIND not found, no unwind support")
  add_library(unwind::unwind INTERFACE IMPORTED)
endif()

unset(UNWIND_INCLUDE_DIR)
unset(UNWIND_LIBRARY)
