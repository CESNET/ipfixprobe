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

#include "osqueryFields.hpp"
#include "osqueryRequestManager.hpp"

namespace ipxp {

class OSQueryPlugin : public ProcessPlugin {
public:
	OSQueryPlugin(const std::string& params, FieldManager& manager);

	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	void onDestroy(void* pluginContext) override;

	std::string getName() const noexcept override;

	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<OSQueryFields> m_fieldHandlers;
	OSQueryRequestManager m_requestManager;
};

} // namespace ipxp
