add_executable(testOutputFieldConfigurationParser
    testOutputFieldConfigurationParser.cpp
)

target_include_directories(testOutputFieldConfigurationParser PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/outputPlugin
	${CMAKE_BINARY_DIR}/src
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

target_link_libraries(testOutputFieldConfigurationParser PRIVATE
    GTest::gtest
    GTest::gtest_main
    ipfixprobe-core
)

add_test(NAME testOutputFieldConfigurationParser COMMAND testOutputFieldConfigurationParser)