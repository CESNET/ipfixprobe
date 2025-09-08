#pragma once

#include <cstddef>

namespace ipxp
{

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
    
} // namespace ipxp
