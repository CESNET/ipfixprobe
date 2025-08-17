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

#include "dnssdExport.hpp"
#include "dnssdFields.hpp"

namespace ipxp {

class DNSSDPlugin : public ProcessPlugin {
public:
	DNSSDPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~DNSSDPlugin() override = default;

	DNSSDPlugin(const DNSSDPlugin& other) = default;
	DNSSDPlugin(DNSSDPlugin&& other) = delete;

private:
	DNSSDExport m_exportData;
	FieldHandlers<DNSSDFields> m_fieldHandlers;

	bool parseDNSSD(
		std::span<const std::byte> payload, 
		const bool isDNSoverTCP,
		FlowRecord& flowRecord) noexcept;


};

} // namespace ipxp
