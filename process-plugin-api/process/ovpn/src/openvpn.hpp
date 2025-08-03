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

#include "openvpnExport.hpp"
#include "openvpnFields.hpp"
#include "openvpnProcessingState.hpp"

namespace ipxp {

class OpenVPNPlugin : public ProcessPlugin {
public:
	OpenVPNPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~OpenVPNPlugin() override = default;

	OpenVPNPlugin(const OpenVPNPlugin& other) = default;
	OpenVPNPlugin(OpenVPNPlugin&& other) = delete;

private:
	FlowAction updateConfidenceLevel(const Packet& packet);

	OpenVPNExport m_exportData;
	FieldHandlers<OpenVPNFields> m_fieldHandlers;
	OpenVPNProcessingState m_processingState;
	
};

} // namespace ipxp
