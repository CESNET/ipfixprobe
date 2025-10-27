/**
 * @file
 * @brief MQTT header types.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::mqtt {

/**
 * @enum MQTTHeaderType
 * @brief Enumerates the header types of MQTT that will be parsed.
 */
enum class MQTTHeaderType : uint8_t {
	CONNECT = 1,
	CONNECT_ACK,
	PUBLISH,
	DISCONNECT = 14,
};

} // namespace ipxp::process::mqtt
