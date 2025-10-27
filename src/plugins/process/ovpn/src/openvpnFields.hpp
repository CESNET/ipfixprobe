/**
 * @file
 * @brief Export fields of OVPN plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::ovpn {

/**
 * @enum OpenVPNFields
 * @brief Enumerates the fields exported by the OVPN plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class OpenVPNFields : std::size_t {
	OVPN_CONF_LEVEL = 0,
	FIELDS_SIZE,
};

} // namespace ipxp::process::ovpn
