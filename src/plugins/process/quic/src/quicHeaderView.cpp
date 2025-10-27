/**
 * @file quicHeaderView.hpp
 * @brief Definition of QUICHeaderView for parsing QUIC packet headers.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "quicHeaderView.hpp"

#include "quicConnectionId.hpp"

#include <arpa/inet.h>
#include <utils/spanUtils.hpp>

namespace ipxp::process::quic {

constexpr static bool hasQUICBitSet(const std::byte firstPayloadByte) noexcept
{
	// Contains value of the first included QUIC bit (in the case of coalesced packets)
	// Always the second msb.
	// Note: no meaning if in Version negotiation.
	constexpr std::byte QUIC_BIT = std::byte {0b01000000};
	return static_cast<bool>(firstPayloadByte & QUIC_BIT);
}

constexpr static bool hasLongHeaderBitSet(const std::byte firstPayloadByte) noexcept
{
	// We  test for 1 in the fist position = long header
	// We ignore the QUIC bit, as it might be greased
	// https://datatracker.ietf.org/doc/html/rfc9287
	return static_cast<bool>(firstPayloadByte & std::byte {0x80});
}

constexpr static bool isSupportedVersion(const QUICVersion& version) noexcept
{
	return version.draft != 0 && version.draft < 255;
}

constexpr static bool hasLongHeader(
	const uint8_t l4Protocol,
	const QUICVersion& version,
	const std::size_t payloadLength) noexcept
{
	// UDP check, Initial packet check, QUIC min long header size, QUIC version check,
	// TODO USE VALUES FROM DISSECTOR
	constexpr uint8_t UDP = 17;

	/* If false
	Packet is not Initial or does not contains LONG HEADER or is not long enough or is "
			"not a supported QUIC version */
	return l4Protocol == UDP && payloadLength >= QUICHeaderView::QUIC_MIN_PACKET_LENGTH
		&& isSupportedVersion(version);
}

constexpr static bool checkHeaderForm(const std::byte headerForm) noexcept
{
	if (!hasQUICBitSet(headerForm)) {
		return false;
	}

	if (!hasLongHeaderBitSet(headerForm)) {
		return false;
	}

	return true;
}

std::optional<QUICHeaderView>
QUICHeaderView::createFrom(std::span<const std::byte> payload, const uint8_t l4Protocol) noexcept
{
	if (payload.size() < MIN_HEADER_SIZE) {
		return std::nullopt;
	}

	std::optional<QUICHeaderView> headerView = QUICHeaderView();

	headerView->headerForm = payload[0];
	if (!checkHeaderForm(headerView->headerForm)) {
		return std::nullopt;
	}

	constexpr std::size_t versionOffset = sizeof(headerForm);
	headerView->version
		= QUICVersion(ntohl(*reinterpret_cast<const uint32_t*>(&payload[versionOffset])));

	if (!hasLongHeader(l4Protocol, *headerView->version, payload.size())) {
		return std::nullopt;
	}

	constexpr std::size_t destConnectionIdLengthOffset = versionOffset + sizeof(uint32_t);
	const uint8_t destConnectionIdLength
		= static_cast<uint8_t>(payload[destConnectionIdLengthOffset]);

	constexpr std::size_t destConnectionIdOffset
		= destConnectionIdLengthOffset + sizeof(destConnectionIdLength);
	if (destConnectionIdOffset + destConnectionIdLength >= payload.size()) {
		return std::nullopt;
	}
	headerView->destinationConnectionId
		= toSpan<const uint8_t>(payload.data() + destConnectionIdOffset, destConnectionIdLength);
	if (headerView->destinationConnectionId.size() > MAX_CONNECTION_ID_LENGTH) {
		// Received DCID longer than supported
		return std::nullopt;
	}

	const std::size_t srcConnectionIdLengthOffset = destConnectionIdOffset + destConnectionIdLength;
	if (srcConnectionIdLengthOffset >= payload.size()) {
		return std::nullopt;
	}
	const uint8_t srcConnectionIdLength
		= static_cast<uint8_t>(payload[srcConnectionIdLengthOffset]);

	const std::size_t srcConnectionIdOffset
		= srcConnectionIdLengthOffset + sizeof(srcConnectionIdLength);
	if (srcConnectionIdOffset + srcConnectionIdLength >= payload.size()) {
		return std::nullopt;
	}
	headerView->sourceConnectionId
		= toSpan<const uint8_t>(payload.data() + srcConnectionIdOffset, srcConnectionIdLength);
	if (headerView->sourceConnectionId.size() > MAX_CONNECTION_ID_LENGTH) {
		// Received SCID longer than supported
		return std::nullopt;
	}

	return headerView;
}

std::size_t QUICHeaderView::getLength() const noexcept
{
	return MIN_HEADER_SIZE + destinationConnectionId.size() + sourceConnectionId.size();
}

QUICHeaderView::PacketType QUICHeaderView::getPacketType() const noexcept
{
	if (version->id == QUICVersionId::version_negotiation) {
		return PacketType::VERSION_NEGOTIATION;
	}

	const uint8_t packetType = (static_cast<uint8_t>(headerForm) & 0b00110000) >> 4;
	if (version->generation != QUICGeneration::V2) {
		switch (packetType) {
		case 0b00:
			return PacketType::INITIAL;
		case 0b01:
			return PacketType::ZERO_RTT;
		case 0b10:
			return PacketType::HANDSHAKE;
		case 0b11:
			return PacketType::RETRY;
		}
	}

	switch (packetType) {
	case 0b00:
		return PacketType::RETRY;
	case 0b01:
		return PacketType::INITIAL;
	case 0b10:
		return PacketType::ZERO_RTT;
	case 0b11:
		return PacketType::HANDSHAKE;
	}

	__builtin_unreachable();
}

} // namespace ipxp::process::quic
