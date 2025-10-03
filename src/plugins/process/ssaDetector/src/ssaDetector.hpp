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

#include "packetStorage.hpp"
#include "ssaDetectorData.hpp"
#include "ssaDetectorFields.hpp"

#include <sstream>
#include <string>

#include <boost/container/static_vector.hpp>
#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp {

class SSADetectorPlugin : public ProcessPlugin {
public:
	/**
	 * @brief Constructs the SSADetector plugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	SSADetectorPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `SSADetectorData` in `pluginContext`. Do nothing for first 30 packets.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Searches for packets that could be TCP syn-synack-ack transitions and add them to
	 * `SSADetectorData`
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `SSADetectorData`.
	 * @return Result of the update.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepares export data.
	 *
	 * Decides whether the flow is tunnel or not based on the number of detected SYN-SYNACK-ACK
	 * sequences. If the confidence is too low, the plugin is removed.
	 *
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to `SSADetectorData`.
	 * @return Result of the export.
	 */
	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Destroys plugin data.
	 *
	 * Calls the destructor of `SSADetectorData` in `pluginContext`.
	 *
	 * @param pluginContext Pointer to `SSADetectorData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides memory layout information for `SSADetectorData`.
	 *
	 * @return Memory layout including size and alignment of `SSADetectorData`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	constexpr void updatePacketsData(
		const std::size_t length,
		const Timestamp timestamp,
		const Direction direction,
		SSADetectorData& pluginData) noexcept;

	FieldHandlers<SSADetectorFields> m_fieldHandlers;
};

} // namespace ipxp
