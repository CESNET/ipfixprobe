/**
 * @file
 * @brief Export fields of FlowHash plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::flowHash {

/**
 * @enum FlowHashFields
 * @brief Enumerates the fields exported by the FlowHash plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class FlowHashFields : std::size_t {
	FLOW_ID = 0,
	FIELDS_SIZE,
};

} // namespace ipxp::process::flowHash
