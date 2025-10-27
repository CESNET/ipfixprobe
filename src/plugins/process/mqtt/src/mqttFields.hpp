/**
 * @file
 * @brief Export fields of MQTT plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::mqtt {

/**
 * @enum MQTTFields
 * @brief Enumerates the fields exported by the MQTT plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class MQTTFields : std::size_t {
	MQTT_TYPE_CUMULATIVE = 0,
	MQTT_VERSION,
	MQTT_CONNECTION_FLAGS,
	MQTT_KEEP_ALIVE,
	MQTT_CONNECTION_RETURN_CODE,
	MQTT_PUBLISH_FLAGS,
	MQTT_TOPICS,
	FIELDS_SIZE,
};

} // namespace ipxp::process::mqtt
