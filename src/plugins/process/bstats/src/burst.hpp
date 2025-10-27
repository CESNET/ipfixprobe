/**
 * @file
 * @brief Burst structure for packet statistics.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <amon/types/Timestamp.hpp>
#include <directionalField.hpp>
#include <sys/time.h>
#include <timestamp.hpp>
#include <utils.hpp>

namespace ipxp::process::burstStats {

/**
 * @struct Burst
 * @brief Structure representing one packet burst. Contains packets, bytes which belong to that
 * burst with begin and end timestamps.
 */
struct Burst {
	// constexpr static timeval MAX_INTERPACKET_TIMEDIFF
	//	= {1, 0}; ///< Maximum time difference between packets in one burst (1 second).
	constexpr static uint64_t MAX_BURST_DURATION_NS = 1'000'000'000; ///< 1 second in nanoseconds.

	std::reference_wrapper<uint32_t> packets;
	std::reference_wrapper<uint32_t> bytes;
	std::reference_wrapper<amon::types::Timestamp> start;
	std::reference_wrapper<amon::types::Timestamp> end;

	/**
	 * @brief Checks if the given timestamp belongs to the burst.
	 *
	 * @param time The timestamp to check.
	 * @return true if the timestamp belongs to the burst, false otherwise.
	 */
	constexpr bool belongs(const amon::types::Timestamp& time) const noexcept
	{
		// TODO operator - for amon::Timestamp
		return time.nanoseconds() - end.get().nanoseconds() < MAX_BURST_DURATION_NS;
	}
};

} // namespace ipxp