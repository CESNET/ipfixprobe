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

#include <sstream>
#include <string>
#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <fieldHandlersEnum.hpp>

#include "mqttData.hpp"
#include "mqttFields.hpp"

namespace ipxp {

/**
 * @class MQTTPlugin
 * @brief A plugin for parsing MQTT traffic.
 */
class MQTTPlugin : public ProcessPlugin {
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
	 * Constructs `MQTTData` in `pluginContext` and initializes it with parsed MQTT data.
	 * Removes plugin if failed to parse MQTT.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates `MQTTData` with parsed data from new packet.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `MQTTData`.
	 * @return Result of the update, requires no more updates if parsing failed.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `MQTTData`.
	 * @param pluginContext Pointer to `MQTTData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `MQTTData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	PluginUpdateResult parseMQTT(std::span<const std::byte> payload, FlowRecord& flowRecord, MQTTData& mqttData) noexcept;

	uint32_t maxTopicsToSave{10};
	FieldHandlers<MQTTFields> m_fieldHandlers;
	
};

} // namespace ipxp
