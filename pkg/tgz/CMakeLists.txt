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

add_custom_target(tgz-msec
	COMMENT "Generating tar.gz package..."
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	COMMAND
		"${GIT_EXECUTABLE}" "archive"
		"--prefix=ipfixprobe-msec-${VERSION}/"
		"--output=${TGZ_FILE_MSEC}"
		"HEAD"
)

add_custom_target(tgz-nemea
	COMMENT "Generating tar.gz package..."
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	COMMAND
		"${GIT_EXECUTABLE}" "archive"
		"--prefix=ipfixprobe-nemea-${VERSION}/"
		"--output=${TGZ_FILE_NEMEA}"
		"HEAD"
)
