# Telemetry library (C++ library for telemetry data collection with Fuse integration)
#
# The Telemetry library consists of two libraries that can be added as dependency:
#
# - telemetry::telemetry (C++ library for telemetry data collection)
# - telemetry::appFs     (C++ library that expose telemetry data as a Fuse filesystem)

#set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG master
)

FetchContent_MakeAvailable(yaml-cpp)


