#pragma once

#include <cstddef>

namespace ipxp
{

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
    
} // namespace ipxp
