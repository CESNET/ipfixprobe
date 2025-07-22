#pragma once

#include <sys/time.h>
#include <directionalField.hpp>
#include <utils.hpp>

namespace ipxp
{

struct Burst {
    
    constexpr static timeval MAX_INTERPACKET_TIMEDIFF = {1, 0};

    uint32_t& packets;
	uint32_t& bytes;
	timeval& start;
	timeval& end;

    constexpr inline
    bool belongs(const timeval& time) const noexcept 
    {
        return time - end < MAX_INTERPACKET_TIMEDIFF;
    }
};


} // namespace ipxp