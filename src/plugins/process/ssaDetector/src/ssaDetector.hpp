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
#include "ssaDetectorContext.hpp"
#include "ssaDetectorFields.hpp"

#include <sstream>
#include <string>

#include <boost/container/static_vector.hpp>
#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::ssaDetector {

class SSADetectorPlugin : public ProcessPluginCRTP<SSADetectorPlugin> {
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
	 * Constructs `SSADetectorContext` in `pluginContext`. Do nothing for first 30 packets.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Searches for packets that could be TCP syn-synack-ack transitions and add them to
	 * `SSADetectorContext`
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `SSADetectorContext`.
	 * @return Result of the update.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepares export data.
	 *
	 * Decides whether the flow is tunnel or not based on the number of detected SYN-SYNACK-ACK
	 * sequences. If the confidence is too low, the plugin is removed.
	 *
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to `SSADetectorContext`.
	 * @return Result of the export.
	 */
	OnExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Destroys plugin data.
	 *
	 * Calls the destructor of `SSADetectorContext` in `pluginContext`.
	 *
	 * @param pluginContext Pointer to `SSADetectorContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides memory layout information for `SSADetectorContext`.
	 *
	 * @return Memory layout including size and alignment of `SSADetectorContext`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void updatePacketsData(
		const amon::Packet& packet,
		const Direction direction,
		SSADetectorContext& ssaContext) noexcept;

	FieldHandlers<SSADetectorFields> m_fieldHandlers;
};

} // namespace ipxp::process::ssaDetector
