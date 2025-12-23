add_executable(testOutputConfigurationParser
    testOutputConfigurationParser.cpp
)

target_include_directories(testOutputConfigurationParser PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/outputPlugin
	${CMAKE_BINARY_DIR}/src
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

target_link_libraries(testOutputConfigurationParser PRIVATE
    GTest::gtest
    GTest::gtest_main
    ipfixprobe-core
)

add_test(NAME testOutputConfigurationParser COMMAND testOutputConfigurationParser)