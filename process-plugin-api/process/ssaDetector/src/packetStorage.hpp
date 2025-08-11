#pragma once

#include <cstddef>
#include <array>

#include <directionalField.hpp>

namespace ipxp
{
    
class PacketStorage {
public:
    constexpr static std::size_t MIN_PACKET_SIZE = 60;
    constexpr static std::size_t MAX_PACKET_SIZE = 150;
    constexpr static std::size_t MAX_PACKET_TIMEDIFF_US = 3'000'000;

    constexpr static bool isValid(const std::size_t length) noexcept 
    {
        return length >= MIN_PACKET_SIZE && length <= MAX_PACKET_SIZE;
    }

    constexpr void insert(
        const std::size_t length, 
        const uint64_t timestamp,
        const Direction direction) noexcept
    {
        timestamps.resize(length - MIN_PACKET_SIZE);
        timestamps[length - MIN_PACKET_SIZE][direction] = timestamp;
    }

    constexpr
    bool hasSimilarPacketsRecently(
        const std::size_t length, 
        const std::size_t maxSizeDiff, 
        const uint64_t now, 
        const Direction direction) noexcept
    {
        const std::size_t startIndex = std::max(
            static_cast<ssize_t>(length - maxSizeDiff - MIN_PACKET_SIZE), 0);
        const std::size_t endIndex = length - MIN_PACKET_SIZE;

        for (std::size_t i = startIndex; i <= endIndex; ++i) {
            if (now > timestamps[i][direction] && 
                now - timestamps[i][direction] < MAX_PACKET_TIMEDIFF_US) {
                return true;
            }
        }
        
        return false;
    }

private:
    std::vector<DirectionalField<uint64_t>> timestamps;
};

} // namespace ipxp
