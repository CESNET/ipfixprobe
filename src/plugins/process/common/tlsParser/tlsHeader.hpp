/**
 * @file
 * @brief Defines the TLSHeader struct for representing TLS record headers.
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
struct TLSHeader {
	enum class Type : uint8_t { HANDSHAKE = 22 };

	Type type;
	TLSVersion version;
	uint16_t length;
	/* Record data... */

} __attribute__((packed));

} // namespace ipxp::process
