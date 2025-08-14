/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file quic_parser.cpp
 * \brief Class for parsing quic traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * \date 2023
 */

#include "quicParser.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <arpa/inet.h> 
#include <array>
#include <limits>

#include "quicVersion.hpp"
#include "quicPacketType.hpp"
#include "quicHeaderView.hpp"

namespace ipxp {

constexpr static
std::optional<std::size_t>
parseRetry(std::span<const std::byte> payload) noexcept
{
	/*const std::optional<VariableLengthInt> token
		= readQUICVariableLengthInt(payload);
	if (!token.has_value()) {
		return std::nullopt;
	}*/

	constexpr std::size_t IntegrityTagSize = 16;
	if (payload.size() < IntegrityTagSize) {
		return std::nullopt;
	}

	packetDirection = QUICDirection::SERVER_TO_CLIENT;
	packetTypesCumulative.bits.retry = true;

	return IntegrityTagSize;
}

constexpr static
std::optional<uint16_t> getServerPortFromInitialHeader(
	const std::optional<QUICInitialHeaderView>& initialHeaderView,
	const uint16_t srcPort,
	const uint16_t dstPort) noexcept
{
	if (!initialHeaderView.has_value()) {
		return std::nullopt;
	}
	if (!initialHeaderView->tlsHandshake.has_value()) {
		return std::nullopt;
	}

	

	return std::nullopt;
}

constexpr static
std::optional<uint16_t> getServerPort(
    const uint16_t srcPort, 
    const uint16_t dstPort,
	const std::optional<QUICInitialHeaderView>& initialHeaderView,
    const PacketType packetType) noexcept
{
	switch (packetType) {
	case PacketType::INITIAL:
		if (!initialHeaderView.has_value() || 
			!initialHeaderView->tlsHandshake.has_value()) {
			return std::nullopt;
		}

        switch (initialHeaderView->tlsHandshake->type)
        {
        case TLSHandshake::Type::CLIENT_HELLO:
            return dstPort;
        case TLSHandshake::Type::SERVER_HELLO:
            return srcPort;
        default:
		    // e.g. ACKs do not reveal direction
            return std::nullopt;
        }
	case PacketType::VERSION_NEGOTIATION: [[fallthrough]]
	case PacketType::RETRY:
		return srcPort;
	case PacketType::ZERO_RTT:
		return dstPort;
	case PacketType::HANDSHAKE:
		// Does not reveal the direction
		return std::nullopt;
	}

	return std::nullopt;
}

constexpr
std::optional<std::size_t> QUICParser::parseZeroRTT(
	std::span<const std::byte> payload) noexcept
{
	const std::optional<VariableLengthInt> restPayloadLength
		= readQUICVariableLengthInt(payload);
	if (!restPayloadLength.has_value()) {
		return std::nullopt;
	}

	if (m_zeroRTTPackets != std::numeric_limits<uint8_t>::max()) {
		m_zeroRTTPackets++;
	}

	packetTypesCumulative.bits.zeroRTT = true;
	packetDirection = QUICDirection::CLIENT_TO_SERVER;

	return restPayloadLength->value + restPayloadLength->length;
}

constexpr
std::optional<std::size_t> QUICParser::parseHandshake(
	std::span<const std::byte> payload) noexcept
{
	const std::optional<VariableLengthInt> restPayloadLength
		= readQUICVariableLengthInt(payload);
	if (!restPayloadLength.has_value()) {
		return std::nullopt;
	}

	if (restPayloadLength->value > MAX_PAYLOAD_BUFFER_SIZE) {
		return false;
	}

	packetTypesCumulative.bits.handshake = true;

	return restPayloadLength->value + restPayloadLength->length;
}

constexpr
std::optional<std::size_t> QUICParser::parseInitial(
	std::span<const std::byte> payload,
	std::span<const uint8_t> currentDCID,
	std::span<const uint8_t> previousDCID,
	const std::byte headerForm,
	std::span<const std::byte> salt,
	const uint16_t srcPort,
	const uint16_t dstPort) noexcept
{
	initialHeaderView = QUICInitialHeaderView::createFrom(currentDCID);
	if (!initialHeaderView.has_value()) {
		initialHeaderView = QUICInitialHeaderView::createFrom(previousDCID);
		if (!initialHeaderView.has_value()) {
			return std::nullopt;
		}
	}

	packetTypesCumulative.bits.initial = true;

	if (initialHeaderView->tlsHandshake->type == TLSHandshake::Type::SERVER_HELLO) {
		packetDirection = QUICDirection::SERVER_TO_CLIENT;
	}
	if (initialHeaderView->tlsHandshake->type == TLSHandshake::Type::CLIENT_HELLO) {
		packetDirection = QUICDirection::CLIENT_TO_SERVER;
	}

	return initialHeaderView->???;
}



bool QUICParser::parse(
	std::span<const std::byte> payload) noexcept
{
	// Handle coalesced packets
	// 7 because (1B QUIC LH, 4B Version, 1 B SCID LEN, 1B DCID LEN)
	constexpr std::size_t MIN_PACKET_SIZE = 8;
	for (std::optional<std::size_t> secondaryHeaderSize = std::nullopt;
		payload.size() >= MIN_PACKET_SIZE;
		payload = payload.subspan(*secondaryHeaderSize)) {

		// TODO CHECK IF SUBSPAN NOT STARTS AFTER SPAN END
		const std::optional<QUICHeaderView> headerView
			= QUICHeaderView::createFrom(payload.subspan(offset));
		if (!headerView.has_value()) {
			break;
		}
		payload = payload.subspan(headerView->getLength());

		const QUICPacketType packetType = headerView->getPacketType();
		switch (packetType) {
		case QUICHeaderView::PacketType::ZERO_RTT: {
			secondaryHeaderSize = parseZeroRTT(...);
			break;
		}
		case QUICHeaderView::PacketType::HANDSHAKE: {
			secondaryHeaderSize = parseHandshake(...);
			break;
		}
		case QUICHeaderView::PacketType::INITIAL: {
			secondaryHeaderSize = parseInitial(...);
			break;
		}
		case QUICHeaderView::PacketType::RETRY: {
			secondaryHeaderSize = parseRetry(payload);
			return true; // ??????????
			break;
		}
		case QUICHeaderView::PacketType::VERSION_NEGOTIATION: {
			packetDirection = QUICDirection::SERVER_TO_CLIENT;
			packetTypesCumulative.bits.versionNegotiation = true;
			return true; // ??????????
			break;
		}
		}

		if (!headerSize.has_value()) {
			return false;
		}

		/*if (packetType == QUICHeaderView::PacketType::RETRY) {
			return true;
		}*/
	}

	return true;
} // QUICPlugin::quic_parse_data


bool QUICParser::quic_check_quic_long_header_packet(
	const uint8_t l4Protocol, std::span<const std::byte> payload,
	char* initial_packet_dcid,
	uint8_t& initial_packet_dcid_length)
{
	initial_dcid_len = initial_packet_dcid_length;
	initial_dcid = (uint8_t*) initial_packet_dcid;

	if (!hasQUICBitSet(packet.payload[0])) {
		return false;
	}

	if (!hasLongHeader(l4Protocol, payload[0])) {
		return false;
	}

	quic_initialze_arrays();
	if (!quic_parse_headers(pkt, false)) {
		return false;
	}
	return true;
}
 // QUICParser::quic_obtain_version

constexpr static
std::optional<QUICHeaderData> parseHeader(std::span<const std::byte> header) noexcept
{
	QUICHeaderData headerData;

	const std::optional<FirstQUICHeader> firstHeader 
		= FirstQUICHeader::createFromPayload(payload);
	if (!firstHeader.has_value()) {
		return std::nullopt;
	}

	const std::optional<std::span<const std::uint8_t, 20>> salt 
		= getSalt(firstHeader->getVersion());
	if (!salt.has_value()) {
		// Error, version not supported;
		return std::nullopt;
	}

	headerData.packetType = QUICPacket::getType(version, firstHeader->headerForm);

	const std::optional<QUICInitialHeaderView> initialHeaderView
		= QUICInitialHeaderView::createFromPayload(payload.subspan());
	if (!initialHeaderView.has_value()) {
		return std::nullopt;
	}

	return headerData;
}


} // namespace ipxp
