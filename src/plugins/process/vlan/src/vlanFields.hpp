/**
 * @file
 * @brief Definition of VLAN fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::vlan {

/**
 * @enum VLANFields
 * @brief Enumerates the fields exported by the VLAN plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class VLANFields : std::size_t {
	VLAN_ID = 0,
	FIELDS_SIZE,
};

} // namespace ipxp::process::vlan
