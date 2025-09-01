#pragma once

#include <sys/time.h>
#include <directionalField.hpp>
#include <utils.hpp>

namespace ipxp
{

struct Burst {
    
    constexpr static uint64_t MAX_INTERPACKET_TIMEDIFF = 1'000'000;

    std::reference_wrapper<uint32_t> packets;
	std::reference_wrapper<uint32_t> bytes;
	std::reference_wrapper<uint64_t> start;
	std::reference_wrapper<uint64_t> end;

    constexpr inline
    bool belongs(const uint64_t& time) const noexcept 
    {
        return time - end < MAX_INTERPACKET_TIMEDIFF;
    }
};


} // namespace ipxp