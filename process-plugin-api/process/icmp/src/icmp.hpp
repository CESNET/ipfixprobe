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

#include "icmpExport.hpp"
#include "icmpFields.hpp"

namespace ipxp {

class ICMPPlugin : public ProcessPlugin {
public:
	ICMPPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~ICMPPlugin() override = default;


	ICMPPlugin(const ICMPPlugin& other) = default;
	ICMPPlugin(ICMPPlugin&& other) = delete;

private:
	ICMPExport m_exportData;
	FieldHandlers<ICMPFields> m_fieldHandlers;
	
};

} // namespace ipxp
