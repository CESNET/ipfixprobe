/**
 * @file
 * @brief Plugin for parsing sip traffic.
 * @author Tomas Jansky <janskto1@fit.cvut.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that calculates packet statistics as flags, acknowledgments, and sequences
 * within flows, stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "sipContext.hpp"
#include "sipFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::sip {

/**
 * @class SIPPlugin
 * @brief A plugin for processing SIP traffic and exporting values.
 *
 * Collects and exports message type, status code, call ID, calling party, called party,
 * via, user agent, command sequence, and request URI.
 *
 */
class SIPPlugin : public ProcessPluginCRTP<SIPPlugin> {
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
	 * Constructs `SIPContext` in `pluginContext` and initializes it with
	 * the parsed SIP values of the first packet.
	 * Removes plugin data if SIP parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Reinserts flow if message code is detected.
	 *
	 * If no message code is detected, the plugin data remains unchanged.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `SIPContext`.
	 * @return Result of the update.
	 */
	BeforeUpdateResult
	beforeUpdate(const FlowContext& flowContext, const void* pluginContext) const override;

	/**
	 * @brief Cleans up and destroys `SIPContext`.
	 * @param pluginContext Pointer to `SIPContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `SIPContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool
	parseSIPData(std::string_view payload, SIPContext& sipContext, FlowRecord& flowRecord) noexcept;

	FieldHandlers<SIPFields> m_fieldHandlers;
};

} // namespace ipxp::process::sip
