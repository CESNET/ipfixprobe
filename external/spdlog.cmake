# spdlog library (modern C++ logger)
#
# Since we don't want to depend on usually outdated system-provided
# library, we use statically linked library.
#
# Following options must be used to override rpmbuild parameters that
# are passed to the library when building.
set(BUILD_SHARED_LIBS OFF)
set(SPDLOG_BUILD_SHARED OFF)

FetchContent_Declare(
	spdlog
	GIT_REPOSITORY "https://github.com/gabime/spdlog.git"
	GIT_TAG "v1.15.1"
	GIT_SHALLOW 1
)

FetchContent_MakeAvailable(spdlog)
