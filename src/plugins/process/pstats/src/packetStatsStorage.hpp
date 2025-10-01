#pragma once

#include <boost/container/static_vector.hpp>
#include <cstddef>
#include <array>
#include <cstdint>
#include <tcpFlags.hpp>

namespace ipxp {

template<std::size_t Size>
struct PacketStatsStorage {
    constexpr PacketStatsStorage() noexcept = default;

    template<std::size_t OtherSize>
    constexpr PacketStatsStorage(const PacketStatsStorage<OtherSize>& other) noexcept
    {
        static_assert(OtherSize <= Size, "Cannot copy from larger storage to smaller storage");
    
        std::ranges::copy(other.lengths, lengths.begin());
        std::ranges::copy(other.tcpFlags, tcpFlags.begin());
        std::ranges::copy(other.timestamps, timestamps.begin());
        std::ranges::copy(other.directions, directions.begin());
    }

    void set(const uint8_t pos, const uint16_t length, const TCPFlags flags, const Timestamp timestamp, const int8_t direction) noexcept
    {
        lengths[pos] = length;
        tcpFlags[pos] = flags;
        timestamps[pos] = timestamp;
        directions[pos] = direction;
    }

    /// Storage for lengths of the packets.
	std::array<uint16_t, Size> lengths;

	/// Storage for TCP flags of the packets.
	std::array<TCPFlags, Size> tcpFlags;

    /// Storage for timestamps of the packets.
	std::array<Timestamp, Size> timestamps;

    /// Storage for directions of the packets.
	std::array<int8_t, Size> directions;
};

} // namespace ipxp