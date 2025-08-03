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

#include "mqttExport.hpp"
#include "mqttFields.hpp"

namespace ipxp {

class MQTTPlugin : public ProcessPlugin {
public:
	MQTTPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~MQTTPlugin() override = default;

	MQTTPlugin(const MQTTPlugin& other) = default;
	MQTTPlugin(MQTTPlugin&& other) = delete;

private:
	FlowAction parseMQTT(std::span<const std::byte> payload, 
		FlowRecord& flowRecord) noexcept;

	MQTTExport m_exportData;
	FieldHandlers<MQTTFields> m_fieldHandlers;
	
};

} // namespace ipxp
