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

#include "rtspExport.hpp"
#include "rtspFields.hpp"

namespace ipxp {

class RTSPPlugin : public ProcessPlugin {
public:
	RTSPPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~RTSPPlugin() override = default;

	RTSPPlugin(const RTSPPlugin& other) = default;
	RTSPPlugin(RTSPPlugin&& other) = delete;

private:
	bool m_requestParsed{false};
	bool m_responseParsed{false};

	RTSPExport m_exportData;
	FieldHandlers<RTSPFields> m_fieldHandlers;

	
};

} // namespace ipxp
