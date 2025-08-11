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

#include "vlanExport.hpp"
#include "vlanFields.hpp"

namespace ipxp {

class VLANPlugin : public ProcessPlugin {
public:
	VLANPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~VLANPlugin() override = default;

	VLANPlugin(const VLANPlugin& other) = default;
	VLANPlugin(VLANPlugin&& other) = delete;

private:
	VLANExport m_exportData;
	FieldHandlers<VLANFields> m_fieldHandlers;
};

} // namespace ipxp
