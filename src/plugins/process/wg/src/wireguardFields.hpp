/**
 * @file
 * @brief Definition of Wireguard fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp {

/**
 * @enum WireguardFields
 * @brief Enumerates the fields exported by the Wireguard plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class WireguardFields : std::size_t {
	WG_CONF_LEVEL = 0,
	WG_SRC_PEER,
	WG_DST_PEER,
	FIELDS_SIZE,
};

} // namespace ipxp
