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

#include "nettisaExport.hpp"
#include "nettisaFields.hpp"

namespace ipxp {

class NetTimeSeriesPlugin : public ProcessPlugin {
public:
	NetTimeSeriesPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~NetTimeSeriesPlugin() override = default;

	NetTimeSeriesPlugin(const NetTimeSeriesPlugin& other) = default;
	NetTimeSeriesPlugin(NetTimeSeriesPlugin&& other) = delete;

private:
	void makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept;
	void makeAllFieldsUnavailable(FlowRecord& flowRecord) noexcept;
	void updateNetTimeSeries(FlowRecord& flowRecord, const Packet& packet) noexcept;

	NetTimeSeriesExport m_exportData;
	FieldHandlers<NetTimeSeriesFields> m_fieldHandlers;
	
};

} // namespace ipxp
