/**
 * @file
 * @brief Request manager implementation that handles query making and responses.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "osqueryRequestManager.hpp"

#include <format>
#include <optional>
#include <ranges>

#include <arpa/inet.h>
#include <sys/wait.h>

namespace ipxp::process::osquery {

OSQueryRequestManager::OSQueryRequestManager()
	: countOfAttempts(0)
{
	m_pollFileDescriptor.events = POLLIN;
	m_pollFileDescriptor.fd = -1;

	for (openOsqueryFD(); !handler.isFatalError() && handler.isOpenError(); openOsqueryFD())
		;
}

OSQueryRequestManager::~OSQueryRequestManager()
{
	closeOsqueryFD();
}

std::optional<JsonParser::AboutOSVersion> OSQueryRequestManager::readInfoAboutOS() noexcept
{
	const std::string_view query
		= "SELECT ov.name, ov.major, ov.minor, ov.build, ov.platform, ov.platform_like, ov.arch, "
		  "ki.version, si.hostname FROM os_version AS ov, kernel_info AS ki, system_info AS "
		  "si;\r\n";

	const auto result = executeQuery(query);
	if (!result.has_value()) {
		return std::nullopt;
	}

	return JsonParser::parseJsonOSVersion(std::string_view(result->data(), result->size()));
}

std::optional<JsonParser::AboutProgram>
OSQueryRequestManager::readInfoAboutProgram(const FlowKey& flowKey) noexcept
{
	if (handler.isFatalError()) {
		return std::nullopt;
	}

	const std::optional<pid_t> pid = getPID(flowKey);
	if (!pid.has_value()) {
		return std::nullopt;
	}

	const std::string query = std::format(
		"SELECT p.name, u.username FROM processes AS p INNER JOIN users AS u ON p.uid=u.uid "
		"WHERE p.pid='{}';\r\n",
		*pid);

	const auto result = executeQuery(query);
	if (!result.has_value()) {
		return std::nullopt;
	}

	return JsonParser::parseJsonAboutProgram(std::string_view(result->data(), result->size()));
}

std::optional<boost::static_string<OSQueryRequestManager::BUFFER_SIZE>>
OSQueryRequestManager::executeQuery(
	std::string_view query,
	const bool reopenFileDescriptor) noexcept
{
	if (reopenFileDescriptor) {
		openOsqueryFD();
	}

	if (handler.isFatalError()) {
		return std::nullopt;
	}

	if (handler.isOpenError()) {
		return executeQuery(query, true);
	}

	handler.refresh();

	if (!writeToOsquery(query)) {
		return executeQuery(query, true);
	}

	const std::optional<boost::static_string<BUFFER_SIZE>> queryResult = readFromOsquery();

	if (handler.isReadError()) {
		return executeQuery(query, true);
	}

	if (handler.isReadSuccess()) {
		countOfAttempts = 0;
		return queryResult;
	}

	return std::nullopt;
}

bool OSQueryRequestManager::writeToOsquery(std::string_view query) noexcept
{
	// If expression is true, a logical error has occurred.
	// There should be no logged errors when executing this method
	if (handler.isErrorState()) {
		handler.setFatalError();
		return false;
	}

	const ssize_t writtenCount
		= write(m_queryingProcess->inputFileDescriptor, query.data(), query.size());
	if (writtenCount == -1) {
		return false;
	}

	return static_cast<std::size_t>(writtenCount) == query.size();
}

template<std::size_t ChunkSize>
static boost::static_string<ChunkSize>
readChunk(const int fileDescriptor, OSQueryStateHandler& handler) noexcept
{
	boost::static_string<ChunkSize> res(ChunkSize, 0);

	const ssize_t bytesRead = read(fileDescriptor, res.data(), res.size());

	if (bytesRead < 5) {
		res.clear();
		handler.setReadError();
		return res;
	}

	res.resize(bytesRead);

	if (static_cast<std::size_t>(bytesRead) < ChunkSize || res[bytesRead - 2] == ']') {
		handler.setReadSuccess();
	}

	return res;
}

template<std::size_t ChunkSize>
static auto makeChunkReader(const int fileDescriptor, OSQueryStateHandler& handler)
{
	return std::views::iota(0)
		| std::views::transform([&](int) { return readChunk<ChunkSize>(fileDescriptor, handler); })
		| std::views::take_while([&handler]([[maybe_unused]] const auto&) {
			   return !handler.isReadSuccess() && !handler.isReadError();
		   });
}

static bool setUpPollFileDescriptor(pollfd& pollFileDescriptor) noexcept
{
	constexpr std::size_t POLL_TIMEOUT = 200; // millis
	pollFileDescriptor.revents = 0;

	const int pollRet = poll(&pollFileDescriptor, 1, POLL_TIMEOUT);

	// ret == -1 -> poll error.
	// ret == 0 -> poll timeout (osquery in json mode always returns at least empty json
	// string("[\n\n]\n"), if no response has been received, this is considered an error).
	return pollRet != -1 && pollRet != 0;
}

std::optional<boost::static_string<OSQueryRequestManager::BUFFER_SIZE>>
OSQueryRequestManager::readFromOsquery() noexcept
{
	// If expression is true, a logical error has occurred.
	// There should be no logged errors when executing this method
	if (handler.isErrorState()) {
		handler.setFatalError();
		return std::nullopt;
	}

	auto res = std::make_optional<boost::static_string<BUFFER_SIZE>>();

	if (!setUpPollFileDescriptor(m_pollFileDescriptor)) {
		handler.setReadError();
		return std::nullopt;
	}
	if (!(m_pollFileDescriptor.revents & POLLIN)) {
		return std::nullopt;
	}

	for (auto chunk : makeChunkReader<CHUNK_SIZE>(m_pollFileDescriptor.fd, handler)) {
		if (res->size() + chunk.size() > res->capacity()) {
			chunk.clear();
		}
		res->append(chunk.begin(), chunk.end());
	}

	if (handler.isReadSuccess()) {
		return res;
	}

	return std::nullopt;
}

void OSQueryRequestManager::openOsqueryFD() noexcept
{
	if (handler.isFatalError()) {
		return;
	}

	// All attempts have been exhausted
	if (countOfAttempts >= MAX_COUNT_OF_ATTEMPTS) {
		handler.setFatalError();
		return;
	}

	closeOsqueryFD();
	killPreviousProcesses();
	handler.reset();
	countOfAttempts++;

	m_queryingProcess = Process::popen2("osqueryi --json 2>/dev/null");
	if (!m_queryingProcess.has_value()) {
		handler.setOpenError();
		return;
	}

	handler.setOpen();
	m_pollFileDescriptor.fd = m_queryingProcess->outputFileDescriptor;
}

void OSQueryRequestManager::closeOsqueryFD() noexcept
{
	if (handler.isOpen()) {
		handler.setClosed();
	}
}

void OSQueryRequestManager::killPreviousProcesses(bool useWhonangOption) const
{
	if (useWhonangOption) {
		waitpid(-1, nullptr, WNOHANG);
	} else if (m_queryingProcess->pid > 0) {
		waitpid(m_queryingProcess->pid, nullptr, 0);
	}
}

/*static IPAddress ntohIPAddress(const IPAddress& ipAddress) noexcept
{
	return ipAddress.isIPv4() ? IPAddress(ntohl(ipAddress.u32[0])) : ipAddress;
}*/

std::optional<pid_t> OSQueryRequestManager::getPID(const FlowKey& flowKey) noexcept
{
	const std::string srcIp = flowKey.srcIp.toString();
	const std::string dstIp = flowKey.dstIp.toString();
	const std::string srcPort = std::to_string(flowKey.srcPort);
	const std::string dstPort = std::to_string(flowKey.dstPort);

	const std::string query = std::format(
		"SELECT pid FROM process_open_sockets WHERE "
		"(local_address='{}' AND "
		"remote_address='{}' AND "
		"local_port='{}' AND "
		"remote_port='{}') OR "
		"(local_address='{}' AND "
		"remote_address='{}' AND "
		"local_port='{}' AND "
		"remote_port='{}') LIMIT 1;\r\n",
		srcIp,
		dstIp,
		srcPort,
		dstPort,
		dstIp,
		srcIp,
		dstPort,
		srcPort);

	const auto queryResult = executeQuery(query);
	if (!queryResult.has_value()) {
		return std::nullopt;
	}

	const std::optional<std::string_view> pid = JsonParser::findValueByKey(
		std::string_view(queryResult->data(), queryResult->size()),
		"pid");
	if (!pid.has_value()) {
		return std::nullopt;
	}

	try {
		return std::stoi(pid->data());
	} catch (...) {
		return std::nullopt;
	}
}

/*OSQueryRequestManager::OSQueryRequestManager(OSQueryRequestManager&& other) noexcept
	: m_pollFileDescriptor(std::move(other.m_pollFileDescriptor)),
	  countOfAttempts(other.countOfAttempts),
	  m_queryingProcess(std::move(other.m_queryingProcess)),
	  handler(std::move(other.handler)),
	  parser(std::move(other.parser))
{
}*/

} // namespace ipxp::process::osquery
