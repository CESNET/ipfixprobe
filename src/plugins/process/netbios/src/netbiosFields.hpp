/**
 * @file
 * @brief Export fields of netbios plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::netbios {

/**
 * @enum NetBIOSFields
 * @brief Enumerates the fields exported by the NetBIOS plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class NetBIOSFields : std::size_t {
	NB_NAME = 0,
	NB_SUFFIX,
	FIELDS_SIZE,
};

} // namespace ipxp::process::netbios
