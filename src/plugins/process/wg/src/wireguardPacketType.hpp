/**
 * @file
 * @brief Definition of Wireguard packet types.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::wireguard {

/**
 * @enum WireguardPacketType
 * @brief Enumerates known Wireguard packet types.
 *
 * These enum values represent different types of Wireguard packets.
 */
enum class WireguardPacketType : uint8_t {
	HANDSHAKE_INIT = 0x01,
	HANDSHAKE_RESPONSE = 0x02,
	COOCKIE_REPLY = 0x03,
	TRANSPORT_DATA = 0x04
};

} // namespace ipxp