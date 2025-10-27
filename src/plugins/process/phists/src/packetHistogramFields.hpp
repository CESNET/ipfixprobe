/**
 * @file
 * @brief Export fields of packet histogram plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp {

/**
 * @enum PacketHistogramFields
 * @brief Enumerates the fields exported by the PacketHistogram plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class PacketHistogramFields : std::size_t {
	S_PHISTS_SIZES = 0,
	S_PHISTS_IPT,
	D_PHISTS_SIZES,
	D_PHISTS_IPT,
	FIELDS_SIZE,
};

} // namespace ipxp
