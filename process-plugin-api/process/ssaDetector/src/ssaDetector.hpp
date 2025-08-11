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

#include "ssaDetectorExport.hpp"
#include "ssaDetectorFields.hpp"
#include "packetStorage.hpp"

namespace ipxp {

class SSADetectorPlugin : public ProcessPlugin {
public:
	SSADetectorPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~SSADetectorPlugin() override = default;

	SSADetectorPlugin(const SSADetectorPlugin& other) = default;
	SSADetectorPlugin(SSADetectorPlugin&& other) = delete;

private:
	SSADetectorExport m_exportData;
	FieldHandlers<SSADetectorFields> m_fieldHandlers;

	PacketStorage m_synPackets;
	PacketStorage m_synAckPackets;
};

} // namespace ipxp
