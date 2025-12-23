/**
 * @file connection.hpp
 * @brief Connection manager for network communication declaration.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */
#pragma once

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <ranges>
#include <string_view>

#include <arpa/inet.h>
#include <fcntl.h>
#include <fileDescriptor/fileDescriptor.hpp>
#include <netdb.h>
#include <poll.h>

namespace ipxp::output::ipfix {

struct ConnectionResult;

/**
 * @class Connection
 * @brief Manages network connections for sending data to a collector.
 */
class Connection {
public:
	/** @enum Mode
	 * @brief Connection mode (Non-blocking TCP or UDP).
	 */
	enum class Mode : uint8_t { NON_BLOCKING_TCP, UDP };

	/**
	 * @brief Constructs a Connection object.
	 * @param host The hostname or IP address of the collector.
	 * @param port The port number of the collector.
	 * @param mode The connection mode (NON_BLOCKING_TCP or UDP).
	 * @param reconnectionTimeout The timeout duration for reconnection attempts.
	 * @param verbose Flag to enable verbose logging.
	 */
	Connection(
		std::string host,
		const uint16_t port,
		const Mode mode,
		const std::chrono::duration<uint32_t> reconnectionTimeout = std::chrono::seconds(30),
		const bool verbose = false) noexcept;

	/**
	 * @brief Sends data to the connected collector.
	 * @param data The data to send.
	 * @return True if the data was sent successfully, false otherwise.
	 */
	bool sendData(std::span<const std::byte> data) noexcept;

	/**
	 * @brief Checks if the connection is currently established.
	 * @return True if connected, false otherwise.
	 */
	bool isConnected() const noexcept { return m_connected; }

	/**
	 * @brief Attempts to reconnect to the collector if not connected.
	 * May fail if reconnection timeout has not elapsed since last attempt.
	 */
	void tryToReconnect() noexcept;

private:
	void checkConnection(ConnectionResult result);

	std::string m_host;
	std::string m_port;
	Mode m_mode;
	bool m_verbose;
	bool m_connected {false};
	std::size_t m_reconnectionAttempts {0};
	std::chrono::duration<uint32_t> m_reconnectionTimeout;
	std::chrono::steady_clock::time_point m_lastReconnectionAttempt;
	ipxp::process::FileDescriptor m_fileDescriptor;
};

} // namespace ipxp::output::ipfix