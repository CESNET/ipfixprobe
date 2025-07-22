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

class BurstStatsPlugin 
	: //private FieldHandlers<BurstStatsFields>, 
	public ProcessPlugin {
public:
	BurstStatsPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~BurstStatsPlugin() override = default;

	void updateBursts(Burst& burst, FlowRecord& flowRecord, const Packet& packet) noexcept;


	BurstStatsPlugin(const BurstStatsPlugin& other) = default;
	BurstStatsPlugin(BurstStatsPlugin&& other) = delete;

private:
	constexpr static std::size_t MINIMAL_PACKETS_COUNT = 3;

	void makeAllFieldsUnavailable(FlowRecord& flowRecord) noexcept; 

	BurstStatsExport m_exportData;
	FieldHandlers<BurstStatsFields> m_fieldHandlers;
	
};

} // namespace ipxp
