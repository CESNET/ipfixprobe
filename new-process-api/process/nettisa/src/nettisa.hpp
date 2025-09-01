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

#include "nettisaData.hpp"
#include "nettisaFields.hpp"

namespace ipxp {

class NetTimeSeriesPlugin : public ProcessPlugin {
public:
	NetTimeSeriesPlugin(const std::string& params, FieldManager& manager);

	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	void onDestroy(void* pluginContext) override;

	std::string getName() const noexcept override;

	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;
	
private:
	void makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept;
	void updateNetTimeSeries(FlowRecord& flowRecord, const Packet& packet, NetTimeSeriesData& pluginData) noexcept;

	FieldHandlers<NetTimeSeriesFields> m_fieldHandlers;
	
};

} // namespace ipxp
