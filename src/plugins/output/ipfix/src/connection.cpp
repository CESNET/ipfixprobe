/**
 * @file connection.cpp
 * @brief Connection manager for network communication implementation.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "connection.hpp"

namespace ipxp::output::ipfix {

class ConnectionResult {
public:
	ConnectionResult(std::string errorMessage)
		: m_errorMessage(std::move(errorMessage))
	{
	}

	ConnectionResult(process::FileDescriptor fileDescriptor)
		: m_fileDescriptor(std::move(fileDescriptor)) {};

	bool isSuccess() const noexcept { return static_cast<bool>(m_fileDescriptor); }

	std::string_view getErrorMessage() const noexcept { return m_errorMessage; }

	process::FileDescriptor getFileDescriptor() noexcept
	{
		return process::FileDescriptor(std::move(m_fileDescriptor));
	}

private:
	std::string m_errorMessage;
	process::FileDescriptor m_fileDescriptor;
};

constexpr static std::string ipToString(const addrinfo& endpoint) noexcept
{
	std::array<char, INET6_ADDRSTRLEN> address;
	inet_ntop(
		endpoint.ai_family,
		(endpoint.ai_family == AF_INET)
			? static_cast<void*>(&reinterpret_cast<sockaddr_in*>(endpoint.ai_addr)->sin_addr)
			: static_cast<void*>(&reinterpret_cast<sockaddr_in6*>(endpoint.ai_addr)->sin6_addr),
		address.data(),
		address.size());
	return std::string(address.data());
}

static bool setNonBlockingMode(ipxp::process::FileDescriptor& fileDescriptor) noexcept
{
	const int flags = ::fcntl(fileDescriptor.get(), F_GETFL, 0);
	if (flags == -1) {
		return false;
	}

	if (::fcntl(fileDescriptor.get(), F_SETFL, flags | O_NONBLOCK) == -1) {
		return false;
	}
}

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

ConnectionResult connect(
	std::string_view host,
	std::string_view port,
	const Connection::Mode mode,
	const bool verbose)
{
	std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addressInfo {nullptr, &::freeaddrinfo};
	addrinfo hints {};
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = mode == Connection::Mode::UDP ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = mode == Connection::Mode::UDP ? IPPROTO_UDP : IPPROTO_TCP;

	if (const int errorCode
		= getaddrinfo(host.data(), port.data(), &hints, std::out_ptr(addressInfo))) {
		return ConnectionResult(
			errorCode == EAI_SYSTEM ? ::strerror(errno) : ::gai_strerror(errorCode));
	}

	for (const addrinfo* endpoint = addressInfo.get(); endpoint != nullptr;
		 endpoint = endpoint->ai_next) {
		if (endpoint->ai_family != AF_INET && endpoint->ai_family != AF_INET6) {
			continue;
		}

		if (verbose) {
			std::cerr << "Connecting to IP " << ipToString(*endpoint) << std::endl;
		}

		auto fileDescriptor = process::FileDescriptor(
			socket(endpoint->ai_family, endpoint->ai_socktype, endpoint->ai_protocol));
		if (!fileDescriptor.hasValue()) {
			continue;
			return ConnectionResult("Socket creation failed: " + std::string(::strerror(errno)));
		}

		if (mode == Connection::Mode::NON_BLOCKING_TCP) {
			setNonBlockingMode(fileDescriptor);
		}
		::connect(fileDescriptor.get(), endpoint->ai_addr, endpoint->ai_addrlen);

		constexpr static std::size_t MAX_RECONNECTION_ATTEMPTS = 10;
		if (!waitForSocketToBeWritable(fileDescriptor, MAX_RECONNECTION_ATTEMPTS)) {
			return ConnectionResult("Could not establish connection.");
		}

		return ConnectionResult(process::FileDescriptor(std::move(fileDescriptor)));
	}

	return ConnectionResult("Could not resolve hostname.");
}

Connection::Connection(
	std::string host,
	const uint16_t port,
	const Mode mode,
	const std::chrono::duration<uint32_t> reconnectionTimeout,
	const bool verbose) noexcept
	: m_host(std::move(host))
	, m_port(std::to_string(port))
	, m_mode(mode)
	, m_verbose(verbose)
	, m_reconnectionTimeout(reconnectionTimeout)
{
	checkConnection(connect(m_host, m_port, m_mode, m_verbose));
}

void Connection::tryToReconnect() noexcept
{
	if (std::chrono::steady_clock::now() - m_lastReconnectionAttempt < m_reconnectionTimeout) {
		return;
	}
	checkConnection(connect(m_host, m_port, m_mode, m_verbose));
}

bool Connection::sendData(const std::span<const std::byte> data) noexcept
{
	if (!m_connected) {
		return false;
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
				return false;
			case EAGAIN:
				// EAGAIN is returned when the socket is non-blocking and the send buffer is full
				// possible wait and stop flag check
				continue;
			default:
				return false;
			}
		}

		/* No error from sendto(), add sent data count to total */
		bytesSent += ret;
	}

	return true;
}

void Connection::checkConnection(ConnectionResult result)
{
	if (!result.isSuccess()) {
		m_connected = false;
		m_reconnectionAttempts++;
		m_lastReconnectionAttempt = std::chrono::steady_clock::now();
	}
	if (!result.isSuccess() && m_verbose) {
		std::cerr << "Connection to " << m_host << ":" << m_port
				  << " failed: " << result.getErrorMessage() << std::endl;
	}

	m_fileDescriptor = std::move(result.getFileDescriptor());
	m_connected = true;
}

} // namespace ipxp::output::ipfix