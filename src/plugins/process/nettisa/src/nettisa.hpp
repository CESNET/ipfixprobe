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

#include "nettisaContext.hpp"
#include "nettisaFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::nettisa {

/**
 * @class NetTimeSeriesPlugin
 * @brief A plugin for collecting and exporting network time series statistics.
 */
class NetTimeSeriesPlugin : public ProcessPluginCRTP<NetTimeSeriesPlugin> {
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
	 * Constructs `NetTimeSeriesContext` in `pluginContext` and initializes it with
	 * with values from first packet.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process, always wants new packets.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates `NetTimeSeriesContext` with length of new packet.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `NetTimeSeriesContext`.
	 * @return Result of the update, always wants new packets.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepare the export data. Calculates final values.
	 *
	 * Removes record if it is too short.
	 * Sets all fields as available otherwise.
	 *
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to `NetTimeSeriesContext`.
	 * @return RemovePlugin if packet count is 1, else no action is required.
	 */
	OnExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `NetTimeSeriesContext`.
	 * @param pluginContext Pointer to `NetTimeSeriesContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `NetTimeSeriesContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void makeAllFieldsAvailable(const FlowRecord& flowRecord) noexcept;
	void updateNetTimeSeries(
		FlowRecord& flowRecord,
		const amon::types::Timestamp packetTimestamp,
		const std::size_t ipPayloadLength,
		NetTimeSeriesContext& nettisaContext) noexcept;

	FieldHandlers<NetTimeSeriesFields> m_fieldHandlers;
};

} // namespace ipxp::process::nettisa
