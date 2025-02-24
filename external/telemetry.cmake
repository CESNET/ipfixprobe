# Telemetry library (C++ library for telemetry data collection with Fuse integration)
#
# The Telemetry library consists of two libraries that can be added as dependency:
#
# - telemetry::telemetry (C++ library for telemetry data collection)
# - telemetry::appFs     (C++ library that expose telemetry data as a Fuse filesystem)

set(TELEMETRY_BUILD_SHARED OFF)
set(TELEMETRY_INSTALL_TARGETS OFF)
set(TELEMETRY_PACKAGE_BUILDER OFF)
set(TELEMETRY_ENABLE_TESTS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(GIT_REPO https://github.com/CESNET/telemetry.git)

FetchContent_Declare(
	telemetry
	GIT_REPOSITORY ${GIT_REPO}
	GIT_TAG v1.1.0
)

# Make sure that subproject accepts predefined build options without warnings.
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)

FetchContent_MakeAvailable(telemetry)
