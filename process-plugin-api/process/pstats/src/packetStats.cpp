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

#include "packetStats.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

namespace ipxp {


static const PluginManifest packetStatsPluginManifest = {
	.name = "pstats",
	.description = "Pstats process plugin for computing packet bursts stats.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*PSTATSOptParser parser;
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<PacketStatsFields>> fields = {
	{PacketStatsFields::PPI_PKT_LENGTHS, "PPI_PKT_LENGTHS"},
	{PacketStatsFields::PPI_PKT_TIMES, "PPI_PKT_TIMES"},
	{PacketStatsFields::PPI_PKT_FLAGS, "PPI_PKT_FLAGS"},
	{PacketStatsFields::PPI_PKT_DIRECTIONS, "PPI_PKT_DIRECTIONS"},
};


static FieldSchema createPacketStatsSchema()
{
	FieldSchema schema("pstats");

	schema.addVectorField<uint16_t>(
		"PPI_PKT_LENGTHS",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const uint16_t> {
			return getSpan(reinterpret_cast<const PacketStatsExport*>(thisPtr)
				->lengths);
		});

	schema.addVectorField<uint8_t>(
		"PPI_PKT_FLAGS",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const uint8_t> {
			return getSpan<const uint8_t>(reinterpret_cast<const PacketStatsExport*>(thisPtr)
				->tcpFlags);
		});
	
	schema.addVectorField<int8_t>(
		"PPI_PKT_DIRECTIONS",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const int8_t> {
			return getSpan(reinterpret_cast<const PacketStatsExport*>(thisPtr)
				->directions);
		});

	// TODO EXPORT TIMEVAL
	return schema;
}

PacketStatsPlugin::PacketStatsPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createPacketStatsSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction PacketStatsPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	updatePacketsData(packet);

	return FlowAction::RequestTrimmedData;
}

FlowAction PacketStatsPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	updatePacketsData(packet);

	return FlowAction::RequestTrimmedData;
}

void PacketStatsPlugin::onFlowExport(FlowRecord& flowRecord) {
	const std::size_t packetsTotal 
		= flowRecord.dataForward.packets + flowRecord.dataReverse.packets;
	
	constexpr static std::size_t MIN_FLOW_LENGTH = 1;
	if (packetsTotal <= MIN_FLOW_LENGTH) {
		return;
	}

	m_fieldHandlers[PacketStatsFields::PPI_PKT_LENGTHS].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_TIMES].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_FLAGS].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_DIRECTIONS].setAsAvailable(flowRecord);
}

constexpr static
bool isSequenceOverflowed(const uint32_t currentValue, const uint32_t prevValue)
{
	constexpr int64_t MAX_DIFF = static_cast<int64_t>(
		static_cast<double>(std::numeric_limits<uint32_t>::max()) / 100);

	return static_cast<int64_t>(currentValue)
		- static_cast<int64_t>(prevValue) < -MAX_DIFF;
}

bool PacketStatsPlugin::isDuplicate(const Packet& packet) noexcept
{
	// TODO USE VALUES FROM DISSECTOR
	constexpr std::size_t TCP = 6;
	if (packet.flowKey.l4Protocol != TCP) {
		return false;
	}

	// Current seq <= previous ack?
	const bool suspiciousSequence 
		= packet.tcpData->sequence <= m_lastSequence[packet.direction]
			&& !isSequenceOverflowed(packet.tcpData->sequence, m_lastSequence[packet.direction]);
	
	// Current ack <= previous ack?
	const bool suspiciousAcknowledgment 
		= packet.tcpData->acknowledgment <= m_lastAcknowledgment[packet.direction]
			&& !isSequenceOverflowed(packet.tcpData->acknowledgment, m_lastAcknowledgment[packet.direction]);

	if (suspiciousSequence && suspiciousAcknowledgment 
		&& packet.payload.size() == m_lastLength[packet.direction]
		&& packet.tcpData->flags == m_lastFlags[packet.direction] 
		&& m_exportData.lengths.size() != 0) {
		return true;
	}

	return false;
}

void PacketStatsPlugin::updatePacketsData(const Packet& packet) noexcept
{
	if (!packet.tcpData.has_value()) {
		return;
	}

	if (m_skipDuplicates && isDuplicate(packet)) {
		return;
	}

	m_lastSequence[packet.direction] = packet.tcpData->sequence;
	m_lastAcknowledgment[packet.direction] = packet.tcpData->acknowledgment;
	m_lastLength[packet.direction] = packet.realLength;
	m_lastFlags[packet.direction] = packet.tcpData->flags;

	if (packet.realLength == 0 && !m_countEmptyPackets) {
		return;
	}

	if (m_exportData.lengths.size() == m_exportData.lengths.capacity()) {
		return;
	}
	
	m_exportData.lengths.push_back(static_cast<uint16_t>(packet.realLength));

	m_exportData.tcpFlags.push_back(packet.tcpData->flags);
	
	m_exportData.timestamps.push_back(packet.timestamp);
	
	/*
	 * direction =  1 iff client -> server
	 * direction = -1 iff server -> client
	 */
	const int8_t direction = packet.direction ? 1 : -1;
	m_exportData.directions.push_back(direction);
}

ProcessPlugin* PacketStatsPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<PacketStatsPlugin*>(constructAtAddress), *this);
}

std::string PacketStatsPlugin::getName() const { 
	return packetStatsPluginManifest.name; 
}

const void* PacketStatsPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<PacketStatsPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	packetStatsRegistrar(packetStatsPluginManifest);

} // namespace ipxp
