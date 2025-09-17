/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <sstream>
#include <string>
#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <fieldHandlersEnum.hpp>

#include "ssdpData.hpp"
#include "ssdpFields.hpp"

namespace ipxp {

class SSDPPlugin : public ProcessPlugin {
public:

	/**
	 * @brief Constructs the SSDP plugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	SSDPPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `SSDPData` in `pluginContext` and initializes it with
	 * parsed SSDP values.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts parsed SSDP values into `SSDPData` from `pluginContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `SSDPData`.
	 * @return Result of the update.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up resources associated with the plugin data.
	 *
	 * Calls the destructor of `SSDPData` to free any allocated resources.
	 *
	 * @param pluginContext Pointer to `SSDPData` to be destroyed.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `PacketStatsData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:

	constexpr void parseSSDP(
		std::string_view payload, SSDPData& pluginData, FlowRecord& flowRecord) noexcept;

	void parseSSDPMSearch(std::string_view headerFields, SSDPData& pluginData, FlowRecord& flowRecord) noexcept;

	void parseSSDPNotify(
		std::string_view headerFields, SSDPData& pluginData, FlowRecord& flowRecord) noexcept;

	FieldHandlers<SSDPFields> m_fieldHandlers;
};

} // namespace ipxp
