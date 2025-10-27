/**
 * @file
 * @brief Export fields of ICMP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::icmp {

/**
 * @enum ICMPFields
 * @brief Enumerates the fields exported by the ICMP plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class ICMPFields : std::size_t {
	L4_ICMP_TYPE_CODE = 0,
	L4_ICMP_CODE,
	L4_ICMP_TYPE,
	FIELDS_SIZE,
};

} // namespace ipxp::process::icmp
