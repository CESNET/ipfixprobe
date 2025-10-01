#pragma once

#include <cstdint>

#include "ipAddress.hpp"

namespace ipxp {

struct FlowKeyLayout {    
    std::size_t size;
    std::size_t alignment;
};

struct FlowKey {
    constexpr static FlowKeyLayout getLayout() noexcept
    {
        return {
            .size = sizeof(FlowKey),
            .alignment = alignof(FlowKey),
        };
    };

	IPAddress srcIp;
	IPAddress dstIp;
	uint16_t srcPort;
	uint16_t dstPort;
	uint8_t l4Protocol;

    constexpr inline
    std::size_t hash() const noexcept 
    {
        return 0; //XXH3_64bits(this, sizeof(*this), 0);
    }
};





} // namespace ipxp