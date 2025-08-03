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

#include "packetHistogramExport.hpp"
#include "packetHistogramFields.hpp"

namespace ipxp {

class PacketHistogramPlugin : public ProcessPlugin {
public:
	PacketHistogramPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~PacketHistogramPlugin() override = default;

	PacketHistogramPlugin(const PacketHistogramPlugin& other) = default;
	PacketHistogramPlugin(PacketHistogramPlugin&& other) = delete;

private:
	void updateExportData(const std::size_t realPacketLength, const uint64_t packetTimestamp, const Direction direction) noexcept;

	PacketHistogramExport m_exportData;
	FieldHandlers<PacketHistogramFields> m_fieldHandlers;
	DirectionalField<std::optional<uint64_t>> m_lastTimestamps;
	bool m_countEmptyPackets{false};

};

} // namespace ipxp
