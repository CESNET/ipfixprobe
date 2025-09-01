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

#include "mplsFields.hpp"

namespace ipxp {

class MPLSPlugin : public ProcessPlugin {
public:
	MPLSPlugin(const std::string& params, FieldManager& manager);

	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	void onDestroy(void* pluginContext) override;

	std::string getName() const noexcept override;

	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<MPLSFields> m_fieldHandlers;
};

} // namespace ipxp
