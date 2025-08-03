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

#include "ntpExport.hpp"
#include "ntpFields.hpp"
#include "ntpHeader.hpp"

namespace ipxp {

class NetworkTimePlugin : public ProcessPlugin {
public:
	NetworkTimePlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~NetworkTimePlugin() override = default;


	NetworkTimePlugin(const NetworkTimePlugin& other) = default;
	NetworkTimePlugin(NetworkTimePlugin&& other) = delete;

private:
	void makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept;
	FlowAction parseNTP(FlowRecord& flowRecord, std::span<const std::byte> payload) noexcept;
	void fillTimestamps(std::span<const std::byte> timestampsPayload) noexcept;
	bool fillNetworkTimeHeader(NetworkTimeHeader networkTimeHeader) noexcept;

	NetworkTimeExport m_exportData;
	FieldHandlers<NetworkTimeFields> m_fieldHandlers;
	
};

} // namespace ipxp
