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

#include "mqttData.hpp"
#include "mqttFields.hpp"

namespace ipxp {

class MQTTPlugin : public ProcessPlugin {
public:
	MQTTPlugin(const std::string& params, FieldManager& manager);

	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	void onDestroy(void* pluginContext) override;

	std::string getName() const noexcept override;

	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	PluginUpdateResult parseMQTT(std::span<const std::byte> payload, FlowRecord& flowRecord, MQTTData& mqttData) noexcept;

	uint32_t maxTopicsToSave{10};
	FieldHandlers<MQTTFields> m_fieldHandlers;
	
};

} // namespace ipxp
