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

#include "idpContentExport.hpp"
#include "idpContentFields.hpp"

namespace ipxp {

class IDPContentPlugin : public ProcessPlugin {
public:
	IDPContentPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~IDPContentPlugin() override = default;

	FlowAction updateContent(FlowRecord& flowRecord, const Packet& packet) noexcept;

	IDPContentPlugin(const IDPContentPlugin& other) = default;
	IDPContentPlugin(IDPContentPlugin&& other) = delete;

private:
	IDPContentExport m_exportData;
	FieldHandlers<IDPContentFields> m_fieldHandlers;
};

} // namespace ipxp
