/**
 * @file burstStatsGetters.hpp
 * @brief Getters for BurstStats plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "burstStatsContext.hpp"

namespace ipxp::process::burstStats {

inline constexpr const BurstStatsContext& asBurstStatsContext(const void* context) noexcept
{
	return *static_cast<const BurstStatsContext*>(context);
}

// BurstStatsField::*BI_BRST_PACKETS
inline constexpr auto getBurstPacketsField = [](const void* context, const Direction direction) {
	return asBurstStatsContext(context).getPackets(direction);
};

// BurstStatsField::*BI_BRST_BYTES
inline constexpr auto getBurstBytesField = [](const void* context, const Direction direction) {
	return asBurstStatsContext(context).getBytes(direction);
};

// BurstStatsField::*BI_BRST_TIME_START
inline constexpr auto getBurstStartTimestampsField
	= [](const void* context, const Direction direction) {
		  return asBurstStatsContext(context).getStartTimestamps(direction);
	  };

// BurstStatsField::*BI_BRST_TIME_END
inline constexpr auto getBurstEndTimestampsField
	= [](const void* context, const Direction direction) {
		  return asBurstStatsContext(context).getEndTimestamps(direction);
	  };

} // namespace ipxp::process::burstStats