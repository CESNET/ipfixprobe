/**
 * @file
 * @brief Provides possible directions of QUIC packet.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

#include <directionalField.hpp>

namespace ipxp::process::quic {

/**
 * @enum QUICDirection
 * @brief Direction of QUIC packet i.e. client-to-server or server-to-client.
 */
enum class QUICDirection : uint8_t {
	CLIENT_TO_SERVER,
	SERVER_TO_CLIENT,
};

} // namespace ipxp::process::quic
