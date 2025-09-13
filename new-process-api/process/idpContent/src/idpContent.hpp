/**
 * @file
 * @brief Plugin for parsing idpcontent traffic.
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that exports packet payloads as IDP content,
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

#include "idpContentFields.hpp"
#include "idpContentData.hpp"

namespace ipxp {

/**
 * @class IDPContentPlugin
 * @brief A plugin for collecting IDP content.
 */
class IDPContentPlugin : public ProcessPlugin {
public:

	/**
	 * @brief Constructs the IDPContent plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	IDPContentPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `IDPContentData` in `pluginContext` and initializes it with
	 * payload of initial packet.
	 * Requires packet from another direction to finish processing.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts payload from reverse direction into `IDPContentData` and finish processing.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `IDPContentData`.
	 * @return Result of the update, requires updates if packet has forward direction.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `IDPContentData`.
	 * @param pluginContext Pointer to `IDPContentData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `IDPContentData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	UpdateRequirement updateContent(FlowRecord& flowRecord, const Packet& packet, IDPContentData& exportData) noexcept;

	FieldHandlers<IDPContentFields> m_fieldHandlers;
};

} // namespace ipxp
