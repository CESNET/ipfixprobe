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

#include <sstream>
#include <string>
#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <fieldHandlersEnum.hpp>

#include "httpData.hpp"
#include "httpFields.hpp"

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
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts parsed HTTP data into `HTTPData`.
	 * If packet is an HTTP request and request was already seen, the flow is flushed with reinsert. 
	 * If packet is an HTTP response and response was already seen, the flow is flushed with reinsert. 
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `HTTPData`.
	 * @return Result of the update, does not require new packets if request and response are already parsed.
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
	constexpr PluginUpdateResult parseHTTP(std::span<const std::byte> payload, FlowRecord& flowRecord, HTTPData& httpData) noexcept;

	FieldHandlers<HTTPFields> m_fieldHandlers;
};

} // namespace ipxp
