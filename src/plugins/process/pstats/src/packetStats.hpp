/**
 * @file
 * @brief Plugin for parsing pstats traffic.
 * @author Tomas Cejka <cejkat@cesnet.cz>
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that calculates packet statistics as flags, acknowledgments, and sequences
 * within flows, stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "packetStatsData.hpp"
#include "packetStatsFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp {

/**
 * @class PacketStatsPlugin
 * @brief A plugin for processing and collecting statistics about packets within flows.
 *
 * Collects packet lengths, TCP flags, acknowledgments, sequences untill
 * the storage is filled.
 *
 * @note Duplicate and empty packets can be optionally skipped.
 */
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
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts TCP acknowledgment, sequence, length and flags into `PacketStatsData`
	 * from `pluginContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `PacketStatsData`.
	 * @return Result of the update, may not require new packets if the packet storage is full.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepare the export data.
	 *
	 * Removes record if it seems to be TCP scan.
	 * Sets all fields as available otherwise.
	 *
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to `PacketStatsData`.
	 * @return Remove plugin if it is TCP scan.
	 */
	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `PacketStatsData`.
	 * @param pluginContext Pointer to `PacketStatsData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `PacketStatsData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	/**
	 * @brief Minimum number of packets required for a flow to be considered valid.
	 */
	constexpr static std::size_t MIN_FLOW_LENGTH = 1;

	void updatePacketsData(
		const amon::Packet& packet,
		const PacketFeatures& features,
		PacketStatsData& pluginData) noexcept;

	/**
	 * @brief Skip packets that repeat ack or seq of last TCP fragment with
	 * same length and flags if set.
	 */
	const bool m_skipDuplicates {true};

	/**
	 * @brief Skips empty packets if set.
	 */
	const bool m_countEmptyPackets {false};

	FieldHandlers<PacketStatsFields> m_fieldHandlers;
};

} // namespace ipxp
