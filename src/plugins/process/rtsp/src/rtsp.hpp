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

#include "rtspContext.hpp"
#include "rtspFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::rtsp {

/**
 * @class RTSPPlugin
 * @brief A plugin for processing RTSP traffic and exporting values.
 *
 * Collects request method, user agent, URI, response status code, server and content type.
 *
 */
class RTSPPlugin : public ProcessPluginCRTP<RTSPPlugin> {
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
	 * Constructs `RTSPContext` in `pluginContext` and initializes it with
	 * parsed RTSP values.
	 * Skip consequent packets if RTSP parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Called before the main per-packet update.
	 *
	 * If a new request or response is parsed and the respective one was already seen,
	 * the flow is flushed and then reinserted.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `RTSPContext`.
	 * @return Result of the pre-update.
	 */
	BeforeUpdateResult
	beforeUpdate(const FlowContext& flowContext, const void* pluginContext) const override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates `RTSPContext` with parsed RTSP values.
	 * Skip consequent packets if RTSP parsing fails or both request and response are already
	 * parsed.
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `RTSPContext`.
	 * @return Result of the update.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `RTSPContext`.
	 * @param pluginContext Pointer to `RTSPContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `RTSPContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool parseRequest(std::string_view payload, RTSPContext& pluginContext) noexcept;
	bool parseResponse(std::string_view payload, RTSPContext& pluginContext) noexcept;
	OnUpdateResult updateExportData(std::string_view payload, RTSPContext& pluginContext) noexcept;

	FieldHandlers<RTSPFields> m_fieldHandlers;
};

} // namespace ipxp::process::rtsp
