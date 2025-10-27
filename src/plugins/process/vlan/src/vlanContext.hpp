/**
 * @file
 * @brief Definition of VLAN data structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::vlan {

/**
 * @struct VLANContext
 * @brief Struct representing VLAN export data.
 */
struct VLANContext {
	uint16_t vlanId;
};

} // namespace ipxp::process::vlan
