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
#include <fieldHandlersEnum.hpp>

#include "smtpExport.hpp"
#include "smtpFields.hpp"

namespace ipxp {

class SMTPPlugin : public ProcessPlugin {
public:
	SMTPPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~SMTPPlugin() override = default;

	SMTPPlugin(const SMTPPlugin& other) = default;
	SMTPPlugin(SMTPPlugin&& other) = delete;

private:
	constexpr
	bool parseResponse(std::string_view payload) noexcept;
	constexpr
	bool parseCommand(std::string_view payload) noexcept;
	constexpr
	FlowAction updateSMTPData(
	std::span<const std::byte> payload, const uint16_t srcPort, const uint16_t dstPort) noexcept;

	SMTPExport m_exportData;
	FieldHandlers<SMTPFields> m_fieldHandlers;

	bool m_isDataTransfer{false};
};

} // namespace ipxp
