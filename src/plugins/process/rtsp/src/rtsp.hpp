/**
 * @file
 * @brief Plugin for parsing RTSP traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses RTSP traffic,
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

#include "rtspData.hpp"
#include "rtspFields.hpp"

namespace ipxp {

/**
 * @class RTSPPlugin
 * @brief A plugin for processing RTSP traffic and exporting values.
 * 
 * Collects request method, user agent, URI, response status code, server and content type.
 * 
 */
class RTSPPlugin : public ProcessPlugin {
public:
	
	/**
	 * @brief Constructs the RTSP plugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	RTSPPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `RTSPData` in `pluginContext` and initializes it with
	 * parsed RTSP values.
	 * Skip consequent packets if RTSP parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates `RTSPData` with parsed RTSP values. 
	 * Skip consequent packets if RTSP parsing fails or both request and response are already parsed.
	 * Flushes with reinsert if request has been parsed and incoming packet is request.
	 * Flushes with reinsert if response has been parsed and incoming packet is response.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `RTSPData`.
	 * @return Result of the update.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `RTSPData`.
	 * @param pluginContext Pointer to `RTSPData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `RTSPData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	constexpr bool parseRequest(std::string_view payload, RTSPData& pluginData) noexcept;
	constexpr bool parseResponse(std::string_view payload, RTSPData& pluginData) noexcept;
	constexpr PluginUpdateResult updateExportData(std::span<const std::byte> payload, RTSPData& pluginData) noexcept;

	FieldHandlers<RTSPFields> m_fieldHandlers;
};

} // namespace ipxp
