#pragma once

#include <cstdint>
#include <cstddef>

namespace ipxp
{
    
/*F_INITIAL = 0b00000001,
		F_ZERO_RTT = 0b00000010,
		F_HANDSHAKE = 0b00000100,
		F_RETRY = 0b00001000,
		F_VERSION_NEGOTIATION = 0b00010000,
		F_QUIC_BIT = 0b10000000*/

union QUICTypesCumulative {
    struct {
        uint8_t quicBit : 1;
        uint8_t reserved : 2;
        uint8_t versionNegotiation : 1;
        uint8_t retry : 1;
        uint8_t handshake : 1;
        uint8_t zeroRTT : 1;
        uint8_t initial : 1;
    } bits;

    std::byte raw;
};

static_assert(sizeof(QUICTypesCumulative) == 1, "Invalid QUICTypesCumulative size");

} // namespace ipxp
