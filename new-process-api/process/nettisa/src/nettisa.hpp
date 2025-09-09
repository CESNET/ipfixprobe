/**
 * @file
 * @brief Plugin for parsing Nettisa flow.
 * @author Josef Koumar koumajos@fit.cvut.cz
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts advanced statistics based on packet lengths,
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

#include "nettisaData.hpp"
#include "nettisaFields.hpp"

namespace ipxp {

/**
 * @class NetTimeSeriesPlugin
 * @brief A plugin for collecting and exporting network time series statistics.
 */
class NetTimeSeriesPlugin : public ProcessPlugin {
public:

	/**
	 * @brief Constructs the NetTimeSeries plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	NetTimeSeriesPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `NetTimeSeriesData` in `pluginContext` and initializes it with
	 * with values from first packet.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process, always wants new packets.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates `NetTimeSeriesData` with length of new packet.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `NetTimeSeriesData`.
	 * @return Result of the update, always wants new packets.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepare the export data. Calculates final values.
	 *
	 * Removes record if it is too short.
	 * Sets all fields as available otherwise.
	 *
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to `NetTimeSeriesData`.
	 * @return RemovePlugin if packet count is 1, else no action is required.
	 */
	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `NetTimeSeriesData`.
	 * @param pluginContext Pointer to `NetTimeSeriesData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `NetTimeSeriesData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;
	
private:
	void makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept;
	void updateNetTimeSeries(FlowRecord& flowRecord, const Packet& packet, NetTimeSeriesData& pluginData) noexcept;

	FieldHandlers<NetTimeSeriesFields> m_fieldHandlers;
	
};

} // namespace ipxp
