/**
 * @file
 * @brief Plugin for parsing pstats traffic.
 * @author Tomas Cejka <cejkat@cesnet.cz>
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
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

#include "packetStatsData.hpp"
#include "packetStatsFields.hpp"

/**
 * @class PacketStatsPlugin
 * @brief A plugin for processing and collecting statistics about packets within flows.
 *
 * This plugin provides functionality to initialize, update, export, and destroy packet statistics
 * for network flows. It manages packet statistics data and interacts with field handlers for
 * exporting relevant statistics.
 *
 * @note Duplicate packets can be skipped and empty packets can be optionally counted.
 */
namespace ipxp {

class PacketStatsPlugin : public ProcessPlugin {
public:
	/**
	 * @brief Constructs the PacketStatsPlugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	PacketStatsPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `PacketStatsData` in `pluginContext` and initializes it with
	 * the first packet's TCP acknowledgment, sequence, length and flag values.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates packet statistics for the current packet in the flow.
	 * @param flowContext Contextual information about the flow.
	 * @param pluginContext Pointer to plugin-specific context data.
	 * @return Result of the update process.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Exports collected packet statistics for the completed flow record.
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to plugin-specific context data.
	 * @return Result of the export process.
	 */
	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys plugin-specific context data.
	 * @param pluginContext Pointer to plugin-specific context data.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Returns the name of the plugin.
	 * @return Plugin name as a string.
	 */
	std::string getName() const noexcept override;

	/**
	 * @brief Provides the memory layout of plugin-specific data.
	 * @return Memory layout description for plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	/**
	* @brief Minimum number of packets required for a flow to be considered valid.
 	*/
	constexpr static std::size_t MIN_FLOW_LENGTH = 1;

	
	void updatePacketsData(const Packet& packet, PacketStatsData& pluginData) noexcept;

	const bool m_skipDuplicates{true};
	const bool m_countEmptyPackets{false};

	FieldHandlers<PacketStatsFields> m_fieldHandlers;
};

} // namespace ipxp
