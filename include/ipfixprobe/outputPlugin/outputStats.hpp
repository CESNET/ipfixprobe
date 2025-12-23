
/**
 * @file
 * @brief Declaration of OutputStats.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @struct OutputStats
 * @brief Structure to hold output plugin statistics.
 */
struct OutputStats {
	uint64_t exported;
	uint64_t bytes;
	uint64_t packets;
	uint64_t dropped;
};

} // namespace ipxp