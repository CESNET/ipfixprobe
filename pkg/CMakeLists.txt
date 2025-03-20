if (NOT RELEASE)
	string(TIMESTAMP RELEASE "%Y%m%d%H%M%S")
endif()

set(TGZ_FILE "${CMAKE_CURRENT_BINARY_DIR}/ipfixprobe-${VERSION}-${RELEASE}.tar.gz")

add_subdirectory(tgz)

if (ENABLE_RPMBUILD)
	add_subdirectory(rpm)
endif()
