/**
 * @file
 * @brief Plugin for parsing bstats traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts packet burst statistics of flows,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "burst.hpp"
#include "burstStatsFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::burstStats {

/**
 * @class BurstStatsPlugin
 * @brief A plugin for collecting packet burst statistics.
 */
class BurstStatsPlugin : public ProcessPluginCRTP<BurstStatsPlugin> {
public:
	/**
	 * @brief Constructs the BurstStats plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	BurstStatsPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `BurstStatsContext` in `pluginContext` and initializes it with
	 * burst containing initial packet.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts new packet into `BurstStatsContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `BurstStatsContext`.
	 * @return Result of the update, may not require new packets if burst storage is full.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepare the export data.
	 *
	 * Removes record if it is too short.
	 * Sets all fields as available otherwise.
	 *
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to `BurstStatsContext`.
	 * @return RemovePlugin if packet count is less than `MINIMAL_PACKETS_COUNT`,
	 * else no action is required.
	 */
	OnExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `BurstStatsContext`.
	 * @param pluginContext Pointer to `BurstStatsContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `BurstStatsContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	constexpr static std::size_t MINIMAL_PACKETS_COUNT
		= 3; ///< Minimal number of packets to consider the flow valid.

	void
	updateBursts(Burst& burst, const amon::Packet& packet, const PacketFeatures& features) noexcept;
	void makeAllFieldsUnavailable(FlowRecord& flowRecord) noexcept;

	FieldHandlers<BurstStatsFields> m_fieldHandlers;
};

} // namespace ipxp::process::burstStats
