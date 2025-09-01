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

#include "burstStatsFields.hpp"
#include "burst.hpp"

namespace ipxp {

class BurstStatsPlugin : public ProcessPlugin {
public:
	BurstStatsPlugin(const std::string& params, FieldManager& manager);

	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	void onDestroy(void* pluginContext) override;

	std::string getName() const noexcept override;

	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;


private:
	constexpr static std::size_t MINIMAL_PACKETS_COUNT = 3;

	void updateBursts(Burst& burst, FlowRecord& flowRecord, const Packet& packet) noexcept;
	void makeAllFieldsUnavailable(FlowRecord& flowRecord) noexcept; 

	FieldHandlers<BurstStatsFields> m_fieldHandlers;
	
};

} // namespace ipxp
