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

//#include <ipfixprobe/byte-utils.hpp>
//#include <ipfixprobe/flowifc.hpp>
//#include <ipfixprobe/ipfix-elements.hpp>
//#include <ipfixprobe/packet.hpp>
//#include <ipfixprobe/processPlugin.hpp>

#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <fieldHandlersEnum.hpp>

#include "basicPlusData.hpp"
#include "basicPlusFields.hpp"

namespace ipxp {

/**
 * \brief Basic flow cache plugin.
 */
class BasicPlusPlugin : public ProcessPlugin {
public:
	BasicPlusPlugin(const std::string& params, FieldManager& manager);

	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	void onDestroy(void* pluginContext) override;

	std::string getName() const noexcept override;

	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<BasicPlusFields> m_fieldHandlers;
};

} // namespace ipxp
