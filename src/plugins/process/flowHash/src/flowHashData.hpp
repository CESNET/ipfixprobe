/**
 * @file
 * @brief Export data of FlowHash plugin.
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
 * @struct FlowHashData
 * @brief Structure containing hash of the flow.
 */
struct FlowHashData {
	uint64_t flowHash;
};  

} // namespace ipxp
