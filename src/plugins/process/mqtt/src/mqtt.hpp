/**
 * @file
 * @brief Plugin for parsing mqtt traffic.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Provides a plugin that extracts MQTT fields from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "mqttContext.hpp"
#include "mqttFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::mqtt {

/**
 * @class MQTTPlugin
 * @brief A plugin for parsing MQTT traffic.
 */
class MQTTPlugin : public ProcessPluginCRTP<MQTTPlugin> {
public:
	/**
	 * @brief Constructs the MQTT plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	MQTTPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `MQTTContext` in `pluginContext` and initializes it with parsed MQTT data.
	 * Removes plugin if failed to parse MQTT.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates `MQTTContext` with parsed data from new packet.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `MQTTContext`.
	 * @return Result of the update, requires no more updates if parsing failed.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `MQTTContext`.
	 * @param pluginContext Pointer to `MQTTContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `MQTTContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	OnUpdateResult parseMQTT(
		std::span<const std::byte> payload,
		FlowRecord& flowRecord,
		MQTTContext& mqttContext) noexcept;

	uint32_t m_maxTopicsToSave {10};
	FieldHandlers<MQTTFields> m_fieldHandlers;
};

} // namespace ipxp::process::mqtt
