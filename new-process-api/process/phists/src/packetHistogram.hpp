/**
 * @file
 * @brief Plugin for parsing phists traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that creates histograms based on packet sizes and inter-arrival times,
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

#include "packetHistogramData.hpp"
#include "packetHistogramFields.hpp"

namespace ipxp {

/**
 * @class PacketHistogramPlugin
 * @brief A plugin for collecting and exporting packet histogram statistics.
 * 
 * Empty packets can optionally be omitted from statistics.
 */
class PacketHistogramPlugin : public ProcessPlugin {
public:

	/**
	 * @brief Constructs the PacketHistogram plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	PacketHistogramPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `PacketHistogramData` in `pluginContext` and initializes histograms
	 * with values from the first packet.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process, always requires new packets.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates histograms of `PacketHistogramData` with length and inter-arrival time.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `PacketHistogramData`.
	 * @return Result of the update, always requires new packets.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepare the export data.
	 *
	 * Removes record if it seems to be TCP scan.
	 * Sets all fields as available otherwise.
	 *
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to `PacketHistogramData`.
	 * @return Remove plugin if it is TCP scan.
	 */
	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `PacketHistogramData`.
	 * @param pluginContext Pointer to `PacketHistogramData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `PacketHistogramData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void updateExportData(
		const std::size_t realPacketLength, const Timestamp packetTimestamp, const Direction direction, PacketHistogramData& pluginData) noexcept;

	bool m_countEmptyPackets{false};

	FieldHandlers<PacketHistogramFields> m_fieldHandlers;
};

} // namespace ipxp
