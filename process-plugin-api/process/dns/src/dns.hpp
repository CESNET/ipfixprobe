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

#include "dnsExport.hpp"
#include "dnsFields.hpp"

namespace ipxp {

class DNSPlugin : public ProcessPlugin {
public:
	DNSPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~DNSPlugin() override = default;

	DNSPlugin(const DNSPlugin& other) = default;
	DNSPlugin(DNSPlugin&& other) = delete;

private:
	constexpr bool DNSPlugin::parseDNS(
	std::span<const std::byte> payload, const bool isDNSOverTCP, FlowRecord& flowRecord) noexcept;

	DNSExport m_exportData;
	FieldHandlers<DNSFields> m_fieldHandlers;

	constexpr bool parseDNS(
	std::span<const std::byte> payload, const bool isDNSOverTCP, FlowRecord& flowRecord) noexcept;

};

} // namespace ipxp
