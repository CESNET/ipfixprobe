/**
 * @file
 * @brief Plugin for parsing HTTP traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts HTTP data from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "httpData.hpp"
#include "httpFields.hpp"
#include "httpParser.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp {

/**
 * @class HTTPPlugin
 * @brief A plugin for parsing HTTP traffic.
 */
class HTTPPlugin : public ProcessPlugin {
public:
	/**
	 * @brief Constructs the HTTP plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	HTTPPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `HTTPData` in `pluginContext`. Tries to insert parsed HTTP data into export data.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Called before the main per-packet update.
	 *
	 * If both request and response are already parsed, no further updates are needed.
	 * If a new request or response is parsed and the respective one was already seen,
	 * the flow is flushed and then reinserted.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `HTTPData`.
	 * @return Result of the pre-update check.
	 */
	PluginUpdateResult beforeUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts parsed HTTP data into `HTTPData`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `HTTPData`.
	 * @return Result of the update..
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `HTTPData`.
	 * @param pluginContext Pointer to `HTTPData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `HTTPData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void
	saveParsedValues(const HTTPParser& parser, FlowRecord& flowRecord, HTTPData& httpData) noexcept;

	FieldHandlers<HTTPFields> m_fieldHandlers;
};

} // namespace ipxp
