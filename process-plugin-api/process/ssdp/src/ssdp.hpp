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

#include "ssdpExport.hpp"
#include "ssdpFields.hpp"

namespace ipxp {

class SSDPPlugin : public ProcessPlugin {
public:
	SSDPPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~SSDPPlugin() override = default;

	SSDPPlugin(const SSDPPlugin& other) = default;
	SSDPPlugin(SSDPPlugin&& other) = delete;

private:

	constexpr void parseSSDP(
		std::string_view payload, const uint8_t l4Protocol) noexcept;
		
	void parseSSDPMSearch(std::string_view headerFields) noexcept;
	
	void parseSSDPNotify(
		std::string_view headerFields, const uint8_t l4Protocol) noexcept;

	SSDPExport m_exportData;
	FieldHandlers<SSDPFields> m_fieldHandlers;
};

} // namespace ipxp
