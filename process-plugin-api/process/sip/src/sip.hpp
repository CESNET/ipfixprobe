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

#include "sipExport.hpp"
#include "sipFields.hpp"

namespace ipxp {

class SIPPlugin : public ProcessPlugin {
public:
	SIPPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~SIPPlugin() override = default;

	SIPPlugin(const SIPPlugin& other) = default;
	SIPPlugin(SIPPlugin&& other) = delete;

private:
	constexpr bool parseSIPData(std::string_view payload) noexcept;

	SIPExport m_exportData;
	FieldHandlers<SIPFields> m_fieldHandlers;

};

} // namespace ipxp
