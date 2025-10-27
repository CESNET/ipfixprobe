/**
 * @file
 * @brief Defines the TLSVersion struct for representing TLS version information.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process {

/**
 * @struct TLSVersion
 * @brief Represents the version of the TLS protocol.
 *
 * This structure holds the major and minor version numbers of the TLS protocol.
 */
struct TLSVersion {
	uint8_t major;
	uint8_t minor;
} __attribute__((packed));

static_assert(sizeof(TLSVersion) == 2, "Invalid TLSVersion size");

} // namespace ipxp::process
