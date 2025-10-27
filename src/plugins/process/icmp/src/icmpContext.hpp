/**
 * @file
 * @brief Export data of ICMP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::icmp {

/**
 * @struct ICMPContext
 * @brief Structure representing ICMP export data.
 */
struct ICMPContext {
	uint16_t typeCode;
};

} // namespace ipxp::process::icmp
