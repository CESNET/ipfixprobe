/**
 * @file
 * @brief Request manager declaration that handles query making and responses.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "jsonParser.hpp"
#include "osqueryStateHandler.hpp"
#include "process.hpp"

#include <array>
#include <cstddef>
#include <optional>
#include <string>

#include <boost/static_string/static_string.hpp>
#include <flowKey.hpp>
#include <poll.h>

namespace ipxp::process::osquery {

/**
 * \brief Manager for communication with osquery
 */
struct OSQueryRequestManager {
	OSQueryRequestManager();

	~OSQueryRequestManager();

	/**
	 * Fills the record with OS values from osquery.
	 */
	std::optional<JsonParser::AboutOSVersion> readInfoAboutOS() noexcept;

	/**
	 * Fills the record with program values from osquery.
	 * @param flowData flow data converted to string.
	 * @return true if success or false.
	 */
	std::optional<JsonParser::AboutProgram> readInfoAboutProgram(const FlowKey& flowKey) noexcept;

private:
	constexpr static std::size_t CHUNK_SIZE = 1024;
	constexpr static std::size_t BUFFER_SIZE = CHUNK_SIZE * 20 + 1;
	constexpr static std::size_t MAX_COUNT_OF_ATTEMPTS = 2;

	/**
	 * Sends a request and receives a response from osquery.
	 * @param query sql query according to osquery standards.
	 * @param reopenFD if true - tries to reopen fd.
	 * @return number of bytes read.
	 */
	std::optional<boost::static_string<BUFFER_SIZE>>
	executeQuery(std::string_view query, bool reopenFileDescriptor = false) noexcept;

	/**
	 * Writes query to osquery input FD.
	 * @param query sql query according to osquery standards.
	 * @return true if success or false.
	 */
	bool writeToOsquery(std::string_view query) noexcept;

	/**
	 * Reads data from osquery output FD.
	 * \note Can change osquery state. Possible changes: READ_ERROR, READ_SUCCESS.
	 * @return number of bytes read.
	 */
	std::optional<boost::static_string<BUFFER_SIZE>> readFromOsquery() noexcept;

	/**
	 * Opens osquery FD.
	 * \note Can change osquery state. Possible changes: FATAL_ERROR, OPEN_FD_ERROR.
	 */
	void openOsqueryFD() noexcept;

	/**
	 * Closes osquery FD.
	 */
	void closeOsqueryFD() noexcept;

	/**
	 * Before reopening osquery tries to kill the previous osquery process.
	 *
	 * If \p useWhonangOption is true then the waitpid() function will be used
	 * in non-blocking mode(can be called before the process is ready to close,
	 * the process will remain in a zombie state). At the end of the application,
	 * a zombie process may remain, it will be killed when the application is closed.
	 * Else if \p useWhonangOption is false then the waitpid() function will be used
	 * in blocking mode(will wait for the process to complete). Will kill all unnecessary
	 * processes, but will block the application until the killed process is finished.
	 *
	 * @param useWhonangOption if true will be used non-blocking mode.
	 */
	void killPreviousProcesses(bool useWhonangOption = true) const;

	/**
	 * Tries to get the process id from table "process_open_sockets".
	 * @param[out] pid      process id.
	 * @param[in]  flowData flow data converted to string.
	 * @return true true if success or false.
	 */
	std::optional<pid_t> getPID(const FlowKey& flowKey) noexcept;

	pollfd m_pollFileDescriptor {};
	std::size_t countOfAttempts {0};
	std::optional<Process> m_queryingProcess;
	OSQueryStateHandler handler;
};

} // namespace ipxp::process::osquery