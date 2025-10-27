/**
 * @file packetStatsGetters.hpp
 * @brief Getters for PacketStats plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "packetStatsContext.hpp"

#include <utils/spanUtils.hpp>

namespace ipxp::process::packet_stats {

inline constexpr const PacketStatsContext& asPacketStatsContext(const void* context) noexcept
{
	return *static_cast<const PacketStatsContext*>(context);
}

// PacketStatsField::PPI_PKT_LENGTHS
inline constexpr auto getPacketLengthsField = [](const void* context) {
	return std::visit(
		[&](const auto& storage) {
			return std::span<const uint16_t>(
				storage->lengths.data(),
				asPacketStatsContext(context).processingState.currentStorageSize);
		},
		asPacketStatsContext(context).storage);
};

// PacketStatsField::PPI_PKT_FLAGS
inline constexpr auto getPacketFlagsField = [](const void* context) -> std::span<const uint8_t> {
	return std::visit(
		[&](const auto& storage) {
			return std::span<const uint8_t>(
				reinterpret_cast<const uint8_t*>(storage->tcpFlags.data()),
				asPacketStatsContext(context).processingState.currentStorageSize);
		},
		asPacketStatsContext(context).storage);
};

// PacketStatsField::PPI_PKT_DIRECTIONS
inline constexpr auto getPacketDirectionsField = [](const void* context) {
	return std::visit(
		[&](const auto& storage) {
			return std::span<const int8_t>(
				storage->directions.data(),
				asPacketStatsContext(context).processingState.currentStorageSize);
		},
		asPacketStatsContext(context).storage);
};

// PacketStatsField::PPI_PKT_TIMES
inline constexpr auto getPacketTimestampsField = [](const void* context) {
	return std::visit(
		[&](const auto& storage) {
			return std::span<const amon::types::Timestamp>(
				storage->timestamps.data(),
				asPacketStatsContext(context).processingState.currentStorageSize);
		},
		asPacketStatsContext(context).storage);
};

} // namespace ipxp::process::packet_stats
