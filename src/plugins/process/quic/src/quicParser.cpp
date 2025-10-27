/**
 * @file quicParser.hpp
 * @brief Parser for QUIC traffic.
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "quicParser.hpp"

#include "quicConnectionId.hpp"
#include "quicHeaderView.hpp"
#include "quicSalt.hpp"
#include "quicVariableInt.hpp"
#include "quicVersion.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <span>

#include <arpa/inet.h>

namespace ipxp::process::quic {

constexpr std::optional<std::size_t>
QUICParser::parseRetry(std::span<const std::byte> payload) noexcept
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

	quicDirection = QUICDirection::SERVER_TO_CLIENT;
	packetTypesCumulative.bitfields.retry = true;

	return IntegrityTagSize;
}

constexpr std::optional<std::size_t>
QUICParser::parseZeroRTT(std::span<const std::byte> payload) noexcept
{
	const std::optional<VariableLengthInt> restPayloadLength = readQUICVariableLengthInt(payload);
	if (!restPayloadLength.has_value()) {
		return std::nullopt;
	}

	if (zeroRTTPackets != std::numeric_limits<uint8_t>::max()) {
		zeroRTTPackets++;
	}

	packetTypesCumulative.bitfields.zeroRTT = true;
	quicDirection = QUICDirection::CLIENT_TO_SERVER;

	return restPayloadLength->value + restPayloadLength->length;
}

constexpr std::optional<std::size_t>
QUICParser::parseHandshake(std::span<const std::byte> payload) noexcept
{
	const std::optional<VariableLengthInt> restPayloadLength = readQUICVariableLengthInt(payload);
	if (!restPayloadLength.has_value()) {
		return std::nullopt;
	}

	if (restPayloadLength->value > QUICContext::MAX_TLS_PAYLOAD_TO_SAVE) {
		return false;
	}

	packetTypesCumulative.bitfields.handshake = true;

	return restPayloadLength->value + restPayloadLength->length;
}

std::optional<std::size_t> QUICParser::parseInitial(
	std::span<const std::byte> payload,
	std::span<const uint8_t> currentDCID,
	const std::optional<ConnectionId>& initialDCID,
	const std::byte headerForm,
	std::span<const std::byte> salt,
	const QUICVersion version,
	const std::size_t primaryHeaderLength) noexcept
{
	initialHeaderView = QUICInitialHeaderView::createFrom(
		payload,
		headerForm,
		salt,
		currentDCID,
		version,
		primaryHeaderLength);
	if (!initialHeaderView.has_value() && initialDCID.has_value()) {
		initialHeaderView = QUICInitialHeaderView::createFrom(
			payload,
			headerForm,
			salt,
			toSpan<const uint8_t>(*initialDCID),
			version,
			primaryHeaderLength);
		if (!initialHeaderView.has_value()) {
			return std::nullopt;
		}
	}

	packetTypesCumulative.bitfields.initial = true;

	if (initialHeaderView->tlsHandshake.type == TLSHandshake::Type::SERVER_HELLO) {
		quicDirection = QUICDirection::SERVER_TO_CLIENT;
	}
	if (initialHeaderView->tlsHandshake.type == TLSHandshake::Type::CLIENT_HELLO) {
		quicDirection = QUICDirection::CLIENT_TO_SERVER;
	}

	return initialHeaderView->getLength();
}

bool QUICParser::parse(
	std::span<const std::byte> payload,
	const std::optional<ConnectionId>& initialConnectionId,
	const uint8_t l4Protocol) noexcept
{
	// Handle coalesced packets
	// 7 because (1B QUIC LH, 4B Version, 1 B SCID LEN, 1B DCID LEN)
	constexpr std::size_t MIN_PACKET_SIZE = 8;
	for (std::optional<std::size_t> secondaryHeaderSize = std::nullopt;
		 payload.size() >= MIN_PACKET_SIZE;
		 payload = payload.subspan(*secondaryHeaderSize)) {
		// TODO CHECK IF SUBSPAN NOT STARTS AFTER SPAN END
		const std::optional<QUICHeaderView> headerView
			= QUICHeaderView::createFrom(payload, l4Protocol);
		if (!headerView.has_value()) {
			break;
		}
		payload = payload.subspan(headerView->getLength());

		const QUICHeaderView::PacketType packetType = headerView->getPacketType();
		switch (packetType) {
		case QUICHeaderView::PacketType::ZERO_RTT: {
			secondaryHeaderSize = parseZeroRTT(payload);
			break;
		}
		case QUICHeaderView::PacketType::HANDSHAKE: {
			secondaryHeaderSize = parseHandshake(payload);
			break;
		}
		case QUICHeaderView::PacketType::INITIAL: {
			const std::optional<std::span<const std::byte>> salt
				= QUICSalt::createFor(*headerView->version);
			if (!salt.has_value()) {
				return false;
			}
			secondaryHeaderSize = parseInitial(
				payload,
				headerView->destinationConnectionId,
				initialConnectionId,
				headerView->headerForm,
				*salt,
				*headerView->version,
				headerView->getLength());
			break;
		}
		case QUICHeaderView::PacketType::RETRY: {
			secondaryHeaderSize = parseRetry(payload);
			return true;
		}
		case QUICHeaderView::PacketType::VERSION_NEGOTIATION: {
			quicDirection = QUICDirection::SERVER_TO_CLIENT;
			packetTypesCumulative.bitfields.versionNegotiation = true;
			break;
		}
		}

		if (!secondaryHeaderSize.has_value() || *secondaryHeaderSize > payload.size()) {
			return false;
		}

		/*if (packetType == QUICHeaderView::PacketType::RETRY) {
			return true;
		}*/
	}

	return true;
} // QUICPlugin::quic_parse_data

/*
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
}*/

} // namespace ipxp::process::quic
