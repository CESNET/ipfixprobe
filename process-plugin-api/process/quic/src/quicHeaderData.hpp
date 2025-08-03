#pragma once

#include <span>

#include "quicPacketType.hpp"
#include "quicHeader.hpp"

namespace ipxp
{
    
struct QUICHeaderData {
	std::span<const uint8_t> destConnectionId;
	std::span<const uint8_t> srcConnectionId;
    QUICPacket::Type packetType;

    constexpr
    std::size_t getHeaderLength() const noexcept 
    {
        return sizeof(FirstQUICHeader)
            + destConnectionId.size()
            + sizeof(uint8_t),
            + srcConnectionId.size();
    }
};

} // namespace ipxp
