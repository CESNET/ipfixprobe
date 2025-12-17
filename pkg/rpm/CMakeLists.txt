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

if (ENABLE_INPUT_SOCK)
	list(APPEND RPMBUILD_ARGS "--with" "input_sock")
endif()

if (ENABLE_INPUT_DPDK)
	list(APPEND RPMBUILD_ARGS "--with" "input_dpdk")
endif()

if (ENABLE_INPUT_NFB)
	list(APPEND RPMBUILD_ARGS "--with" "input_nfb")
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

set(SOURCE_TGZ_MSEC "ipfixprobe-msec-${VERSION}.tar.gz")
set(SPEC_FILE_IN_MSEC "${CMAKE_CURRENT_SOURCE_DIR}/ipfixprobe-msec.spec.in")
set(SPEC_FILE_MSEC "${RPMBUILD_DIR}/SPECS/ipfixprobe-msec.spec")
set(RPMBUILD_ARGS_MSEC
	"-ba" "${SPEC_FILE_MSEC}"
	"--define" "_topdir ${RPMBUILD_DIR}/"
)

configure_file("${SPEC_FILE_IN_MSEC}" "${SPEC_FILE_MSEC}" @ONLY)

add_custom_target(rpm-msec
	COMMENT "Generating SRPM and RPM packages for ipfixprobe-msec..."
	WORKING_DIRECTORY "${RPMBUILD_DIR}"

	COMMAND "${CMAKE_COMMAND}" "-E" "copy" "${TGZ_FILE_MSEC}" "SOURCES/${SOURCE_TGZ_MSEC}"
	COMMAND "${RPMBUILD_EXECUTABLE}" ${RPMBUILD_ARGS_MSEC}
)

set(SOURCE_TGZ_NEMEA "ipfixprobe-nemea-${VERSION}.tar.gz")
set(SPEC_FILE_IN_NEMEA "${CMAKE_CURRENT_SOURCE_DIR}/ipfixprobe-nemea.spec.in")
set(SPEC_FILE_NEMEA "${RPMBUILD_DIR}/SPECS/ipfixprobe-nemea.spec")
set(RPMBUILD_ARGS_NEMEA
	"-ba" "${SPEC_FILE_NEMEA}"
	"--define" "_topdir ${RPMBUILD_DIR}/"
)

if (ENABLE_OUTPUT_UNIREC)
	list(APPEND RPMBUILD_ARGS_NEMEA "--with" "output_unirec")
endif()

if (ENABLE_PROCESS_EXPERIMENTAL)
	list(APPEND RPMBUILD_ARGS_NEMEA "--with" "process_experimental")
endif()

configure_file("${SPEC_FILE_IN_NEMEA}" "${SPEC_FILE_NEMEA}" @ONLY)

add_custom_target(rpm-nemea
	COMMENT "Generating SRPM and RPM packages for ipfixprobe-nemea..."
	WORKING_DIRECTORY "${RPMBUILD_DIR}"

	COMMAND "${CMAKE_COMMAND}" "-E" "copy" "${TGZ_FILE_NEMEA}" "SOURCES/${SOURCE_TGZ_NEMEA}"
	COMMAND "${RPMBUILD_EXECUTABLE}" ${RPMBUILD_ARGS_NEMEA}
)

add_dependencies(
	rpm
	tgz
)

add_dependencies(
	rpm-msec
	tgz-msec
)

add_dependencies(
	rpm-nemea
	tgz-nemea
)

add_custom_command(TARGET rpm POST_BUILD
	COMMENT "SRPM and RPM packages are located in ${RPMBUILD_DIR}/"
	COMMAND ;
)

add_custom_command(TARGET rpm-msec POST_BUILD
	COMMENT "SRPM and RPM packages are located in ${RPMBUILD_DIR}/"
	COMMAND ;
)

add_custom_command(TARGET rpm-nemea POST_BUILD
	COMMENT "SRPM and RPM packages are located in ${RPMBUILD_DIR}/"
	COMMAND ;
)
