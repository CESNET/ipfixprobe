#pragma once

#include "quicVersion.hpp"

namespace ipxp
{


// TODO REMOVE FILE

namespace QUICPacket {

constexpr static
PacketType getType(const QUICVersion& version, const std::byte headerForm) noexcept
{
	if (version.id == QUICVersionId::version_negotiation) {
		return PacketType::VERSION_NEGOTIATION;
	}

	const uint8_t packetType 
	= (static_cast<uint8_t>(headerForm) & 0b00110000) >> 4;
	if (version.generation != QUICGeneration::V2) {
		switch (packetType) {
		case 0b00: return PacketType::INITIAL;
		case 0b01: return PacketType::ZERO_RTT;
		case 0b10: return PacketType::HANDSHAKE;
		case 0b11: return PacketType::RETRY;
		}
	}

	switch (packetType) {
	case 0b00: return PacketType::RETRY;
	case 0b01: return PacketType::INITIAL;
	case 0b10: return PacketType::ZERO_RTT;
	case 0b11: return PacketType::HANDSHAKE;
	}

	__builtin_unreachable();
}


}

} // namespace ipxp
