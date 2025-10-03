#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <vector>

#include <directionalField.hpp>

namespace ipxp {

class PacketStorage {
public:
	constexpr static std::size_t MIN_PACKET_SIZE = 60;
	constexpr static std::size_t MAX_PACKET_SIZE = 150;
	constexpr static std::size_t MAX_PACKET_TIMEDIFF_NS
		= std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds(3)).count();

	constexpr static bool isValid(const std::size_t length) noexcept
	{
		return length >= MIN_PACKET_SIZE && length <= MAX_PACKET_SIZE;
	}

	constexpr void
	insert(const std::size_t length, const Timestamp timestamp, const Direction direction) noexcept
	{
		timestamps.resize(length - MIN_PACKET_SIZE);
		timestamps[length - MIN_PACKET_SIZE][direction] = timestamp;
	}

	constexpr bool hasSimilarPacketsRecently(
		const std::size_t length,
		const std::size_t maxSizeDiff,
		const Timestamp now,
		const Direction direction) noexcept
	{
		const std::size_t endIndex = length - MIN_PACKET_SIZE;
		const std::size_t startIndex = endIndex > maxSizeDiff ? endIndex - maxSizeDiff : 0;

		for (std::size_t i = startIndex; i <= endIndex; ++i) {
			if (now > timestamps[i][direction]
				&& (now - timestamps[i][direction]).ns < MAX_PACKET_TIMEDIFF_NS) {
				return true;
			}
		}

		return false;
	}

	void clear() noexcept { timestamps.clear(); }

private:
	std::vector<DirectionalField<Timestamp>> timestamps;
};

} // namespace ipxp
