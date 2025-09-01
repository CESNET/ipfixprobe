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

#include "rtspData.hpp"
#include "rtspFields.hpp"

namespace ipxp {

class RTSPPlugin : public ProcessPlugin {
public:
	RTSPPlugin(const std::string& params, FieldManager& manager);

	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	void onDestroy(void* pluginContext) override;

	std::string getName() const noexcept override;

	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	constexpr bool parseRequest(std::string_view payload) noexcept;
	constexpr bool parseResponse(std::string_view payload) noexcept;
	constexpr FlowAction updateExportData(
		std::span<const std::byte> payload) noexcept;

	FieldHandlers<RTSPFields> m_fieldHandlers;
};

} // namespace ipxp
