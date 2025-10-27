/**
 * @file mqttGetters.hpp
 * @brief Getters for MQTT plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */
#pragma once

#include "mqttContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::mqtt {

inline constexpr const MQTTContext& asMQTTContext(const void* context) noexcept
{
	return *static_cast<const MQTTContext*>(context);
}

// MQTTFields::MQTT_TYPE_CUMULATIVE
inline constexpr auto getMQTTTypeCumulativeField
	= [](const void* context) { return asMQTTContext(context).typeCumulative; };

// MQTTFields::MQTT_VERSION
inline constexpr auto getMQTTVersionField
	= [](const void* context) { return asMQTTContext(context).version; };

// MQTTFields::MQTT_CONNECTION_FLAGS
inline constexpr auto getMQTTConnectionFlagsField
	= [](const void* context) { return asMQTTContext(context).connectionFlags; };
// MQTTFields::MQTT_KEEP_ALIVE
inline constexpr auto getMQTTKeepAliveField
	= [](const void* context) { return asMQTTContext(context).keepAlive; };

// MQTTFields::MQTT_CONNECTION_RETURN_CODE
inline constexpr auto getMQTTConnectionReturnCodeField
	= [](const void* context) { return asMQTTContext(context).connectionReturnCode; };

// MQTTFields::MQTT_PUBLISH_FLAGS
inline constexpr auto getMQTTPublishFlagsField
	= [](const void* context) { return asMQTTContext(context).publishFlags; };

// MQTTFields::MQTT_TOPICS
inline constexpr auto getMQTTTopicsField
	= [](const void* context) { return toStringView(asMQTTContext(context).topics); };

} // namespace ipxp::process::mqtt
