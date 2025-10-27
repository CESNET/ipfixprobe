/**
 * @file
 * @brief Definition of Wireguard packet sizes.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::wireguard {

/**
 * @enum WireguardPacketSize
 * @brief Enumerates known Wireguard packet sizes.
 *
 * These enum values represent the sizes of different types of Wireguard packets.
 */
enum class WireguardPacketSize : std::size_t {
	HANDSHAKE_INIT_SIZE = 148,
	HANDSHAKE_RESPONSE_SIZE = 92,
	COOCKIE_REPLY_SIZE = 64,
	MIN_TRANSPORT_DATA_SIZE = 32
};

} // namespace ipxp