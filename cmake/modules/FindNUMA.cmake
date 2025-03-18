# ~~~
# - Try to find NUMA include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(NUMA)
#
# Variables defined by this module:
#
#  NUMA_FOUND                System has NUMA include and library dirs found
#  NUMA_INCLUDE_DIR          The NUMA include directories.
#  NUMA_LIBRARY              The NUMA library
# ~~~

find_library(NUMA_LIBRARY numa)
find_path(NUMA_INCLUDE_DIR numa.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  NUMA
  REQUIRED_VARS NUMA_INCLUDE_DIR NUMA_LIBRARY
  FAIL_MESSAGE "NUMA not found! Try to install numactl-devel package.")

if(NUMA_FOUND AND NOT TARGET numa::numa)
  add_library(numa::numa INTERFACE IMPORTED)
  set_property(TARGET numa::numa PROPERTY INTERFACE_LINK_LIBRARIES "${NUMA_LIBRARY}")
  set_property(TARGET numa::numa PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${NUMA_INCLUDE_DIR}")
endif()
