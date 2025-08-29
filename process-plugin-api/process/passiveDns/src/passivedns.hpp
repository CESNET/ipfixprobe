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

#include "passivednsExport.hpp"
#include "passivednsFields.hpp"

namespace ipxp {

class PassiveDNSPlugin : public ProcessPlugin {
public:
	PassiveDNSPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~PassiveDNSPlugin() override = default;

	PassiveDNSPlugin(const PassiveDNSPlugin& other) = default;
	PassiveDNSPlugin(PassiveDNSPlugin&& other) = delete;

private:
	void parseDNS(
		std::span<const std::byte> payload,
		FlowRecord& flowRecord,
		const uint8_t l4Protocol) noexcept;

	PassiveDNSExport m_exportData;
	FieldHandlers<PassiveDNSFields> m_fieldHandlers;
};

} // namespace ipxp
