find_package(Git REQUIRED)

add_custom_target(tgz
	COMMENT "Generating tar.gz package..."
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	COMMAND
		"${GIT_EXECUTABLE}" "archive"
		"--prefix=ipfixprobe-${VERSION}/"
		"--output=${TGZ_FILE}"
		"HEAD"
)
