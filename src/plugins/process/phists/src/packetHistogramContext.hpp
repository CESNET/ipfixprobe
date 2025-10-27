/**
 * @file
 * @brief Export data of packet histogram plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <array>
#include <optional>

#include <directionalField.hpp>

namespace ipxp::process::packet_histogram {

/**
 * @struct PacketHistogramContext
 * @brief Struct representing flow packet histogram statistics based on lengths and inter-arrival
 * times.
 */
struct PacketHistogramContext {
	constexpr static std::size_t HISTOGRAM_SIZE = 8;
	DirectionalField<std::array<uint32_t, HISTOGRAM_SIZE>> packetLengths;
	DirectionalField<std::array<uint32_t, HISTOGRAM_SIZE>> packetTimediffs;

	struct {
		DirectionalField<std::optional<uint64_t>> lastTimestamps;
	} processingState;
};

} // namespace ipxp::process::packet_histogram
