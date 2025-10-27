/**
 * @file
 * @brief Defines the TLSHandshake struct for representing TLS handshake messages.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "tlsVersion.hpp"

#include <cstdint>

namespace ipxp::process {

/**
 * @struct TLSHandshake
 * @brief Represents a TLS handshake message with its type, length, and version.
 *
 * This structure is used to parse and represent the initial handshake messages
 * in the TLS protocol, such as ClientHello and ServerHello.
 */
struct TLSHandshake {
	enum class Type : uint8_t { CLIENT_HELLO = 1, SERVER_HELLO = 2 };

	Type type;
	uint8_t length1; // length field is 3 bytes long...
	uint16_t length2;
	TLSVersion version;

	/* Handshake data... */
} __attribute__((packed));

} // namespace ipxp::process
