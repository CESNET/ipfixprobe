/**
 * @file packetHistogramGetters.hpp
 * @brief Getters for PacketHistogram plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "packetHistogramContext.hpp"

#include <utils/spanUtils.hpp>

namespace ipxp::process::packet_histogram {

inline constexpr const PacketHistogramContext&
asPacketHistogramContext(const void* context) noexcept
{
	return *static_cast<const PacketHistogramContext*>(context);
}

inline constexpr auto getPacketTimediffsField = [](const void* context,
												   const Direction direction) noexcept {
	return toSpan<const uint32_t>(asPacketHistogramContext(context).packetTimediffs[direction]);
};

inline constexpr auto getPacketLengthsField
	= [](const void* context, const Direction direction) noexcept {
		  return toSpan<const uint32_t>(asPacketHistogramContext(context).packetLengths[direction]);
	  };

} // namespace ipxp::process::packet_histogram
