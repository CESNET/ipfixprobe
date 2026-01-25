#pragma once

#include "connection.hpp"
#include "tcpConnection.hpp"
#include "udpConnection.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace ipxp::output::ipfix {

class ConnectionFactory {
public:
	/**
	 * @enum Mode
	 * @brief Connection mode (Non-blocking TCP or UDP).
	 */
	enum class Mode : uint8_t { NON_BLOCKING_TCP, BLOCKING_TCP, UDP };

	static std::unique_ptr<Connection> createConnection(
		const Mode mode,
		std::string host,
		const uint16_t port,
		const std::chrono::duration<uint32_t> reconnectionTimeout = std::chrono::seconds(30),
		const bool verbose = false) noexcept
	{
		switch (mode) {
		case Mode::NON_BLOCKING_TCP:
		case Mode::BLOCKING_TCP:
			return std::make_unique<TCPConnection>(
				std::move(host),
				port,
				reconnectionTimeout,
				verbose,
				mode == Mode::BLOCKING_TCP);
		case Mode::UDP:
			return std::make_unique<UDPConnection>(
				std::move(host),
				port,
				reconnectionTimeout,
				verbose);
		}

		return nullptr;
	}
};

} // namespace ipxp::output::ipfix