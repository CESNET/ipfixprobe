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

#include "httpExport.hpp"
#include "httpFields.hpp"

namespace ipxp {

class HTTPPlugin : public ProcessPlugin {
public:
	HTTPPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~HTTPPlugin() override = default;

	HTTPPlugin(const HTTPPlugin& other) = default;
	HTTPPlugin(HTTPPlugin&& other) = delete;

private:
	constexpr FlowAction parseHTTP(
	std::span<const std::byte> payload, FlowRecord& flowRecord) noexcept;
	
	bool m_requestParsed{false};
	bool m_responseParsed{false};

	HTTPExport m_exportData;
	FieldHandlers<HTTPFields> m_fieldHandlers;
};

} // namespace ipxp
