/**
 * @file
 * @brief Provides OVPN finite state machine implementation.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "openvpnProcessingState.hpp"

namespace ipxp::process::ovpn {

void OpenVPNProcessingState::processHardResetFromClient(const IPAddressVariant& srcIp) noexcept
{
	m_state = State::RESET_CLIENT;
	m_invalidPacketCount = 0;
	m_clientIp = srcIp;
}

void OpenVPNProcessingState::processHardResetFromServer(const IPAddressVariant& dstIp) noexcept
{
	if (m_state == State::RESET_CLIENT && m_clientIp == dstIp) { // server to client
		m_state = State::RESET_SERVER;
		m_invalidPacketCount = 0;
		return;
	}
	m_invalidPacketCount++;
	if (m_invalidPacketCount == INVALID_PACKET_THRESHOLD) {
		m_state = State::INVALID;
	}
}

void OpenVPNProcessingState::processControl(
	const IPAddressVariant& srcIp,
	const IPAddressVariant& dstIp,
	const bool hasTLSClientHello) noexcept
{
	if (m_state == State::ACK && m_clientIp == srcIp && hasTLSClientHello) { // client to server
		m_state = State::CLIENT_HELLO;
		m_invalidPacketCount = 0;
		return;
	}
	if (m_state == State::CLIENT_HELLO && m_clientIp == dstIp
		&& hasTLSClientHello) { // server to client
		m_state = State::SERVER_HELLO;
		m_invalidPacketCount = 0;
		return;
	}
	if (m_state == State::SERVER_HELLO || m_state == State::CONTROL_ACK) {
		m_state = State::CONTROL_ACK;
		m_invalidPacketCount = 0;
		return;
	}
	m_invalidPacketCount++;
	if (m_invalidPacketCount == INVALID_PACKET_THRESHOLD) {
		m_state = State::INVALID;
	}
}

void OpenVPNProcessingState::processAck(const IPAddressVariant& srcIp) noexcept
{
	if (m_state == State::RESET_SERVER && m_clientIp == srcIp) {
		m_state = State::ACK;
		m_invalidPacketCount = 0;
		return;
	}
	if (m_state == State::SERVER_HELLO || m_state == State::CONTROL_ACK) {
		m_state = State::CONTROL_ACK;
		m_invalidPacketCount = 0;
	}
}

void OpenVPNProcessingState::processData(
	const std::size_t packetLength,
	const bool isValidRTPHeader) noexcept
{
	if (m_state == State::CONTROL_ACK || m_state == State::DATA) {
		m_state = State::DATA;
		m_invalidPacketCount = 0;
	}

	if (packetLength > MINIMAL_DATA_PACKET_SIZE && !isValidRTPHeader) {
		m_dataPacketCount++;
	}
}

void OpenVPNProcessingState::processOpcode(
	const OpenVPNOpcode opcode,
	const IPAddressVariant& srcIp,
	const IPAddressVariant& dstIp,
	const bool hasTLSClientHello,
	const bool isValidRTPHeader,
	const std::size_t packetLength) noexcept
{
	m_invalidPacketCount++;
	switch (opcode) {
	case OpenVPNOpcode::P_CONTROL_HARD_RESET_CLIENT_V1:
		[[fallthrough]];
	case OpenVPNOpcode::P_CONTROL_HARD_RESET_CLIENT_V2:
		[[fallthrough]];
	case OpenVPNOpcode::P_CONTROL_HARD_RESET_CLIENT_V3:
		processHardResetFromClient(srcIp);
		break;

	case OpenVPNOpcode::P_CONTROL_HARD_RESET_SERVER_V1:
		[[fallthrough]];
	case OpenVPNOpcode::P_CONTROL_HARD_RESET_SERVER_V2:
		processHardResetFromServer(dstIp);
		break;

	case OpenVPNOpcode::P_CONTROL_SOFT_RESET_V1:
		break;

	case OpenVPNOpcode::P_CONTROL_V1:
		processControl(srcIp, dstIp, hasTLSClientHello);
		break;

	case OpenVPNOpcode::P_ACK_V1:
		processAck(srcIp);
		break;

	case OpenVPNOpcode::P_DATA_V1:
		[[fallthrough]];
	case OpenVPNOpcode::P_DATA_V2:
		processData(packetLength, isValidRTPHeader);
		break;

	default:
		break;
	}

	if (packetLength > MINIMAL_DATA_PACKET_SIZE && !isValidRTPHeader) {
		m_largePacketCount++;
	}

	// packets that did not make a valid transition
	constexpr std::size_t INVALID_PACKET_THRESHOLD = 4;
	if (m_invalidPacketCount >= INVALID_PACKET_THRESHOLD) {
		m_state = State::INVALID;
		m_invalidPacketCount = 0;
	}
}

std::optional<uint8_t>
OpenVPNProcessingState::getCurrentConfidenceLevel(const std::size_t packetsTotal) const noexcept
{
	constexpr std::size_t MIN_PACKETS_IN_FLOW = 5;
	if (packetsTotal > MIN_PACKETS_IN_FLOW && m_state == State::DATA) {
		return 100;
	}

	constexpr double LARGE_DATA_PACKET_RATIO = 0.6;
	if (m_largePacketCount > MIN_PACKETS_IN_FLOW
		&& (static_cast<double>(m_dataPacketCount) / static_cast<double>(m_largePacketCount)
			>= LARGE_DATA_PACKET_RATIO)) {
		return static_cast<uint8_t>((
			static_cast<double>(m_dataPacketCount) / static_cast<double>(m_largePacketCount) * 80));
	}

	return std::nullopt;
}

} // namespace ipxp::process::ovpn
