#pragma once

#include <cstdint>
#include <type_traits>
#include <bit>
#include <arpa/inet.h>

namespace ipxp
{

template <typename T>
T toHostByteOrder(T value) {
    static_assert(std::is_integral_v<T>, "T must be an integral type");
    static_assert(sizeof(T) <= 8, "Unsupported integer size");

    if constexpr (std::endian::native == std::endian::big) {
        return value;
    }

    if constexpr (sizeof(T) == 1) {
        return value;
    }
    
    if constexpr (sizeof(T) == 2) {
        return static_cast<T>(ntohs(static_cast<uint16_t>(value)));
    }

    if constexpr (sizeof(T) == 4) {
        return static_cast<T>(ntohl(static_cast<uint32_t>(value)));
    } 
    
    if constexpr (sizeof(T) == 8) {
        uint64_t high = ntohl(static_cast<uint32_t>(value >> 32));
        uint64_t low  = ntohl(static_cast<uint32_t>(value & 0xFFFFFFFFULL));
        return static_cast<T>((low << 32) | high);
    } 
}

    
} // namespace ipxp
