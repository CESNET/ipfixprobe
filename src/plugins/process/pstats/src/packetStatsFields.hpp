/**
 * @file
 * @brief Export fields of packet stats plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::packet_stats {

/**
 * @enum PacketStatsFields
 * @brief Enumerates the fields exported by the PacketStats plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class PacketStatsFields : std::size_t {
	PPI_PKT_LENGTHS = 0,
	PPI_PKT_TIMES,
	PPI_PKT_FLAGS,
	PPI_PKT_DIRECTIONS,
	FIELDS_SIZE,
};

} // namespace ipxp::process::packet_stats
