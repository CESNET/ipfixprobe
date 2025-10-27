/**
 * @file
 * @brief Definition of SSDP fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::ssdp {

/**
 * @enum SSDPFields
 * @brief Enumerates the fields exported by the SSDP plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class SSDPFields : std::size_t {
	SSDP_LOCATION_PORT = 0,
	SSDP_NT,
	SSDP_SERVER,
	SSDP_ST,
	SSDP_USER_AGENT,
	FIELDS_SIZE,
};

} // namespace ipxp::process::ssdp
