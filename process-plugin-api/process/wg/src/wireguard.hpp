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

#include "wireguardExport.hpp"
#include "wireguardFields.hpp"

namespace ipxp {

class WireguardPlugin : public ProcessPlugin {
public:
	WireguardPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~WireguardPlugin() override = default;

	WireguardPlugin(const WireguardPlugin& other) = default;
	WireguardPlugin(WireguardPlugin&& other) = delete;

private:

	constexpr FlowAction parseWireguard(
		std::span<const std::byte> payload, const Direction direction) noexcept;

	WireguardExport m_exportData;
	FieldHandlers<WireguardFields> m_fieldHandlers;
};

} // namespace ipxp
