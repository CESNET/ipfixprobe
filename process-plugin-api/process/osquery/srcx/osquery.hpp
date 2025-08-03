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

#include "osqueryExport.hpp"
#include "osqueryFields.hpp"
#include "osqueryRequestManager.hpp"

namespace ipxp {

class OSQueryPlugin : public ProcessPlugin {
public:
	OSQueryPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~OSQueryPlugin() override = default;

	OSQueryPlugin(const OSQueryPlugin& other) = default;
	OSQueryPlugin(OSQueryPlugin&& other) = delete;

private:
	OSQueryExport m_exportData;
	FieldHandlers<OSQueryFields> m_fieldHandlers;
	OSQueryRequestManager manager;
};

} // namespace ipxp
