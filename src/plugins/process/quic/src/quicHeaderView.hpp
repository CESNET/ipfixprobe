/**
 * @file quicHeaderView.hpp
 * @brief Declaration of QUICHeaderView for parsing QUIC packet headers.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "quicVersion.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace ipxp::process::quic {

class QUICHeaderView {
public:
	constexpr static std::size_t MIN_HEADER_SIZE = 7;
	constexpr static std::size_t QUIC_MIN_PACKET_LENGTH = 8;

	enum class PacketType { INITIAL = 0, ZERO_RTT, HANDSHAKE, RETRY, VERSION_NEGOTIATION = 7 };

	std::byte headerForm;
	std::optional<QUICVersion> version;
	// uint8_t destConnectionIdLength;
	std::span<const uint8_t> destinationConnectionId;
	// uint8_t srcConnectionIdLength;
	std::span<const uint8_t> sourceConnectionId;

	static std::optional<QUICHeaderView>
	createFrom(std::span<const std::byte> payload, const uint8_t l4Protocol) noexcept;

	std::size_t getLength() const noexcept;

	PacketType getPacketType() const noexcept;

private:
};

} // namespace ipxp::process::quic
