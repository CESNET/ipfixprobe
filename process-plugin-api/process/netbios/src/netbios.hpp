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

#include "netbiosExport.hpp"
#include "netbiosFields.hpp"

namespace ipxp {

class NetBIOSPlugin : public ProcessPlugin {
public:
	NetBIOSPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~NetBIOSPlugin() override = default;

	FlowAction parseNetBIOS(FlowRecord& flowRecord, std::span<const std::byte> payload) noexcept;

	NetBIOSPlugin(const NetBIOSPlugin& other) = default;
	NetBIOSPlugin(NetBIOSPlugin&& other) = delete;

private:
	NetBIOSExport m_exportData;
	FieldHandlers<NetBIOSFields> m_fieldHandlers;
	
};

} // namespace ipxp
