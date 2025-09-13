/**
 * @file
 * @brief Plugin for parsing sip traffic.
 * @author Tomas Jansky <janskto1@fit.cvut.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that calculates packet statistics as flags, acknowledgments, and sequences within flows,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <sstream>
#include <string>
#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <fieldHandlersEnum.hpp>

#include "sipData.hpp"
#include "sipFields.hpp"

namespace ipxp {

class SIPPlugin : public ProcessPlugin {
public:
	
	/**
	 * @brief Constructs the SIP plugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	SIPPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `SIPData` in `pluginContext` and initializes it with
	 * the parsed SIP values of the first packet.
	 * Removes plugin data if SIP parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;


	/**
	 * @brief Reinserts flow if message code is detected.
	 *
	 * If no message code is detected, the plugin data remains unchanged.
	 * 
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `SIPData`.
	 * @return Result of the update.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `SIPData`.
	 * @param pluginContext Pointer to `SIPData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `SIPData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	constexpr bool parseSIPData(std::string_view payload, SIPData& pluginData, FlowRecord& flowRecord) noexcept;

	FieldHandlers<SIPFields> m_fieldHandlers;
};

} // namespace ipxp
