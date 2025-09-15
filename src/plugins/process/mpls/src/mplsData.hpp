/**
 * @file
 * @brief Export data of MPLS plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp
{

/**
 * @struct MPLSData
 * @brief Class representing MPLS export data. Contains the top label for MPLS packets.
 */
struct MPLSData {
	uint32_t topLabel;	
};  

} // namespace ipxp

