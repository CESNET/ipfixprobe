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

#include "packetStatsExport.hpp"
#include "packetStatsFields.hpp"

namespace ipxp {

class PacketStatsPlugin : public ProcessPlugin {
public:
	PacketStatsPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~PacketStatsPlugin() override = default;

	PacketStatsPlugin(const PacketStatsPlugin& other) = default;
	PacketStatsPlugin(PacketStatsPlugin&& other) = delete;

private:
	void updatePacketsData(const Packet& packet) noexcept;
	bool isDuplicate(const Packet& packet) noexcept;

	PacketStatsExport m_exportData;
	FieldHandlers<PacketStatsFields> m_fieldHandlers;

	DirectionalField<uint32_t> m_lastSequence;
	DirectionalField<uint32_t> m_lastAcknowledgment;
	DirectionalField<std::size_t> m_lastLength;
	DirectionalField<TcpFlags> m_lastFlags;

	const bool m_skipDuplicates{true};
	const bool m_countEmptyPackets{false};

};

} // namespace ipxp
