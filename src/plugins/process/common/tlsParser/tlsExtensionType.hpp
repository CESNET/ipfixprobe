/**
 * @file
 * @brief Defines the TLSExtensionType enum for identifying TLS extension types.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process {

/**
 * @enum TLSExtensionType
 * @brief Enumerates the types of TLS extensions.
 *
 * This enum defines various TLS extension types identified by their respective type codes.
 */
enum class TLSExtensionType : uint16_t {
	SERVER_NAME = 0,
	SUPPORTED_GROUPS = 10, // AKA supported_groups, ECLIPTIC_CURVES
	ELLIPTIC_CURVE_POINT_FORMATS = 11,
	SIGNATURE_ALGORITHMS = 13,
	ALPN = 16,
	SUPPORTED_VERSION = 43,
	QUIC_TRANSPORT_PARAMETERS = 0xffa5,
	QUIC_TRANSPORT_PARAMETERS_V1 = 0x39,
	QUIC_TRANSPORT_PARAMETERS_V2 = 0x26
};

} // namespace ipxp::process
