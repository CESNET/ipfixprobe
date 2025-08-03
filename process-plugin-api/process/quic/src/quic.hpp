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

#include "burstStatsExport.hpp"
#include "burstStatsFields.hpp"

namespace ipxp {

class QUICPlugin : public ProcessPlugin {
public:
	QUICPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~QUICPlugin() override = default;

	void updateBursts(Burst& burst, FlowRecord& flowRecord, const Packet& packet) noexcept;


	QUICPlugin(const QUICPlugin& other) = default;
	QUICPlugin(QUICPlugin&& other) = delete;

private:
	BurstStatsExport m_exportData;
	FieldHandlers<BurstStatsFields> m_fieldHandlers;
	
};

} // namespace ipxp
