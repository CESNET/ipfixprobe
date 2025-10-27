/**
 * @file
 * @brief Provides OVPN finite state machine declaration.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "openvpnOpcode.hpp"

#include <ipAddress.hpp>

namespace ipxp::process::ovpn {

/**
 * @class OpenVPNProcessingState
 * @brief A class that handles transitions between OpenVPN processing states.
 */
class OpenVPNProcessingState {
public:
	enum class State {
		INVALID,
		RESET_CLIENT,
		RESET_SERVER,
		ACK,
		CLIENT_HELLO,
		SERVER_HELLO,
		CONTROL_ACK,
		DATA
	};

	void processOpcode(
		const OpenVPNOpcode opcode,
		const IPAddressVariant& srcIp,
		const IPAddressVariant& dstIp,
		const bool hasTLSClientHello,
		const bool isValidRTPHeader,
		const std::size_t packetLength) noexcept;

	std::optional<uint8_t> getCurrentConfidenceLevel(const std::size_t packetsTotal) const noexcept;

private:
	constexpr static std::size_t MINIMAL_DATA_PACKET_SIZE = 500;
	constexpr static std::size_t INVALID_PACKET_THRESHOLD = 4;

	void processHardResetFromClient(const IPAddressVariant& srcIp) noexcept;
	void processHardResetFromServer(const IPAddressVariant& dstIp) noexcept;
	void processControl(
		const IPAddressVariant& srcIp,
		const IPAddressVariant& dstIp,
		const bool hasTLSClientHello) noexcept;
	void processAck(const IPAddressVariant& srcIp) noexcept;
	void processData(const std::size_t packetLength, const bool isValidRTPHeader) noexcept;

	State m_state {State::INVALID};
	std::size_t m_largePacketCount {0};
	std::size_t m_dataPacketCount {0};
	std::size_t m_invalidPacketCount {0};
	IPAddressVariant m_clientIp;
};

} // namespace ipxp::process::ovpn
