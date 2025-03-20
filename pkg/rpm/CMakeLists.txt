find_program(RPMBUILD_EXECUTABLE NAMES rpmbuild REQUIRED)

set(RPMBUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/rpmbuild")

file(MAKE_DIRECTORY
	"${RPMBUILD_DIR}/BUILD"
	"${RPMBUILD_DIR}/RPMS"
	"${RPMBUILD_DIR}/SOURCES"
	"${RPMBUILD_DIR}/SPECS"
	"${RPMBUILD_DIR}/SRPMS"
)

set(SOURCE_TGZ "ipfixprobe-${VERSION}.tar.gz")
set(SPEC_FILE_IN "${CMAKE_CURRENT_SOURCE_DIR}/ipfixprobe.spec.in")
set(SPEC_FILE "${RPMBUILD_DIR}/SPECS/ipfixprobe.spec")
set(RPMBUILD_ARGS
	"-ba" "${SPEC_FILE}"
	"--define" "_topdir ${RPMBUILD_DIR}/"
)

if (ENABLE_INPUT_PCAP)
	list(APPEND RPMBUILD_ARGS "--with" "input_pcap")
endif()

if (ENABLE_INPUT_DPDK)
	list(APPEND RPMBUILD_ARGS "--with" "input_dpdk")
endif()

if (ENABLE_INPUT_NFB)
	list(APPEND RPMBUILD_ARGS "--with" "input_nfb")
endif()

if (ENABLE_OUTPUT_UNIREC)
	list(APPEND RPMBUILD_ARGS "--with" "output_unirec")
endif()

if (ENABLE_PROCESS_EXPERIMENTAL)
	list(APPEND RPMBUILD_ARGS "--with" "process_experimental")
endif()

configure_file("${SPEC_FILE_IN}" "${SPEC_FILE}" @ONLY)

add_custom_target(rpm
	COMMENT "Generating SRPM and RPM packages..."
	WORKING_DIRECTORY "${RPMBUILD_DIR}"

	COMMAND "${CMAKE_COMMAND}" "-E" "copy" "${TGZ_FILE}" "SOURCES/${SOURCE_TGZ}"
	COMMAND "${RPMBUILD_EXECUTABLE}" ${RPMBUILD_ARGS}
)

add_dependencies(
	rpm
	tgz
)

add_custom_command(TARGET rpm POST_BUILD
	COMMENT "SRPM and RPM packages are located in ${RPMBUILD_DIR}/"
	COMMAND ;
)
