# Try to find libatomic
# Once done, this will define
#
# ATOMIC_FOUND        - system has libatomic
# ATOMIC_LIBRARIES    - libraries needed to use libatomic
#

find_library(ATOMIC_LIBRARY
	NAMES atomic libatomic.so.1
	HINTS ${ATOMIC_ROOT} ${CMAKE_INSTALL_LIBDIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args (Atomic
	REQUIRED_VARS ATOMIC_LIBRARY
)

if (ATOMIC_FOUND AND NOT TARGET atomic::atomic)
	add_library(atomic::atomic STATIC IMPORTED)
	set_target_properties(atomic::atomic PROPERTIES
		IMPORTED_LOCATION "${ATOMIC_LIBRARY}"
		INTERFACE_INCLUDE_DIRECTORIES "${ATOMIC_INCLUDE_DIR}")
	target_compile_definitions(atomic::atomic INTERFACE UNWIND_FOUND)
else()
	message(CRITICAL "Notice: atomic not found")
	add_library(atomic::atomic INTERFACE IMPORTED)
endif()

unset(ATOMIC_LIBRARY)
