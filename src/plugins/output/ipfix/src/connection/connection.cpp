/**
 * @file connection.cpp
 * @brief Connection manager for network communication implementation.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "connection.hpp"

#include "connectionResult.hpp"

namespace ipxp::output::ipfix {

static bool
isSocketConnected(ipxp::process::FileDescriptor& fileDescriptor, const int timeoutMs) noexcept
{
	pollfd pollFileDescriptor {};
	pollFileDescriptor.fd = fileDescriptor.get();
	pollFileDescriptor.events = POLLOUT;

	const int pollResult = ::poll(&pollFileDescriptor, 1, timeoutMs);

	if (pollResult < 0)
		return false;
	if (pollResult == 0)
		return false;

	if (pollFileDescriptor.revents & (POLLOUT | POLLERR | POLLHUP)) {
		int socket_error = 0;
		socklen_t len = sizeof(socket_error);

		if (getsockopt(fileDescriptor.get(), SOL_SOCKET, SO_ERROR, &socket_error, &len) < 0) {
			return false;
		}

		return socket_error == 0;
	}

	return false;
}

static bool waitForSocketToBeWritable(
	ipxp::process::FileDescriptor& fileDescriptor,
	const std::size_t connectionAttempts) noexcept
{
	return std::ranges::any_of(
		std::views::iota(std::size_t {0}, connectionAttempts),
		[&](const std::size_t) { return isSocketConnected(fileDescriptor, 10000); });
}

Connection::Connection(
	std::string host,
	const uint16_t port,
	const TransportProtocol protocol,
	const std::chrono::duration<uint32_t> reconnectionTimeout,
	const bool verbose) noexcept
	: m_host(std::move(host))
	, m_port(std::to_string(port))
	, m_verbose(verbose)
	, m_reconnectionTimeout(reconnectionTimeout)
{
	std::expected<AddressInfoList, std::string> addressInfoList
		= AddressInfoList::makeAddressInfoList(m_host, m_port, protocol);
	if (!addressInfoList.has_value()) {
		throw std::runtime_error("Failed to resolve " + m_host + ": " + m_port);
	}
	m_addressInfoList.emplace(std::move(*addressInfoList));
	// checkConnection(connect(AddressInfoList(m_host, m_port, m_mode, m_verbose));
}

void Connection::tryToReconnect() noexcept
{
	if (std::chrono::steady_clock::now() - m_lastReconnectionAttempt < m_reconnectionTimeout) {
		return;
	}
	checkConnection(connect(*m_addressInfoList));
}

Connection::SendStatus Connection::sendData(const std::span<const std::byte> data) noexcept
{
	const Connection::SendStatus status = std::invoke([&]() {
		if (!m_connected) {
			tryToReconnect();
			if (!m_connected) {
				return SendStatus::FAILURE;
			}
			return SendStatus::RECONNECTED;
		}
		return SendStatus::SUCCESS;
	});
	if (status == SendStatus::FAILURE) {
		return SendStatus::FAILURE;
	}

	std::size_t bytesSent = 0;
	while (bytesSent < data.size()) {
		const ssize_t ret = ::send(
			m_fileDescriptor.get(),
			data.subspan(bytesSent).data(),
			data.subspan(bytesSent).size(),
			0);

		if (ret == -1) {
			switch (errno) {
			case 0:
				break;
			case ECONNRESET:
				[[fallthrough]];
			case EINTR:
				[[fallthrough]];
			case ENOTCONN:
				[[fallthrough]];
			case ENOTSOCK:
				[[fallthrough]];
			case EPIPE:
				[[fallthrough]];
			case EHOSTUNREACH:
				[[fallthrough]];
			case ENETDOWN:
				[[fallthrough]];
			case ENETUNREACH:
				[[fallthrough]];
			case ENOBUFS:
				[[fallthrough]];
			case ENOMEM:
				m_connected = false;
				return SendStatus::FAILURE;
			case EAGAIN:
				// EAGAIN is returned when the socket is non-blocking and the send buffer is full
				// possible wait and stop flag check
				continue;
			default:
				return SendStatus::FAILURE;
			}
		}

		/* No error from sendto(), add sent data count to total */
		bytesSent += ret;
	}

	return status;
}

void Connection::checkConnection(ConnectionResult result)
{
	if (!result.isSuccess()) {
		m_connected = false;
		m_reconnectionAttempts++;
		m_lastReconnectionAttempt = std::chrono::steady_clock::now();
	}
	if (!result.isSuccess() && m_verbose) {
		std::print(
			std::cerr,
			"Connection to {}:{} failed: {}\n",
			m_host,
			m_port,
			result.getErrorMessage());
	}

	m_fileDescriptor = std::move(result.getFileDescriptor());
	m_connected = true;
}

std::optional<process::FileDescriptor> Connection::makeSocket(const addrinfo& addressInfo) noexcept
{
	using namespace std::string_literals;
	if (m_verbose) {
		std::print(std::cerr, "Connecting to IP {}\n", addressInfo);
	}

	auto fileDescriptor = process::FileDescriptor(
		socket(addressInfo.ai_family, addressInfo.ai_socktype, addressInfo.ai_protocol));
	if (!fileDescriptor.hasValue() && m_verbose) {
		std::cerr << "Socket creation failed: " << ::strerror(errno) << std::endl;
	}
	if (!fileDescriptor.hasValue()) {
		return std::nullopt;
	}

	::connect(fileDescriptor.get(), addressInfo.ai_addr, addressInfo.ai_addrlen);

	constexpr static std::size_t MAX_RECONNECTION_ATTEMPTS = 10;
	if (!waitForSocketToBeWritable(fileDescriptor, MAX_RECONNECTION_ATTEMPTS)) {
		return std::nullopt;
	}

	return std::make_optional<process::FileDescriptor>(
		process::FileDescriptor(std::move(fileDescriptor)));
}

} // namespace ipxp::output::ipfix