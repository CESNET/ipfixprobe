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

namespace ipxp {

/**
 * @struct VLANData
 * @brief Struct representing VLAN export data.
 */
struct VLANData {
	uint16_t vlanId;
};

} // namespace ipxp
