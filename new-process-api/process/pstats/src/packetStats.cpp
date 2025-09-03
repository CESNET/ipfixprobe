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

static void createPacketStatsSchema(FieldManager& manager, FieldHandlers<PacketStatsFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("pstats");

	handlers.insert(PacketStatsFields::PPI_PKT_LENGTHS, schema.addVectorField(
		"PPI_PKT_LENGTHS",
		[](const void* context) {return toSpan(reinterpret_cast<const PacketStatsExport*>(context)->lengths);
	}));
	handlers.insert(PacketStatsFields::PPI_PKT_FLAGS, schema.addVectorField(
		"PPI_PKT_FLAGS",
		[](const void* context) {return toSpan<const uint8_t>(reinterpret_cast<const PacketStatsExport*>(context)->tcpFlags);
	}));
	handlers.insert(PacketStatsFields::PPI_PKT_DIRECTIONS, schema.addVectorField(
		"PPI_PKT_DIRECTIONS",
		[](const void* context) { return getSpan(reinterpret_cast<const PacketStatsExport*>(context)->directions);
	}));
	handlers.insert(PacketStatsFields::PPI_PKT_TIMES, schema.addVectorField(
		"PPI_PKT_TIMES",
		[](const void* context) {return toSpan(reinterpret_cast<const PacketStatsExport*>(context)->timestamps);
	}));
}

PacketStatsPlugin::PacketStatsPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createPacketStatsSchema(manager, m_fieldHandlers);
}

PluginInitResult PacketStatsPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<PacketStatsData*>(pluginContext));
	updatePacketsData(flowContext.packet, *pluginData);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult PacketStatsPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<PacketStatsData*>(pluginContext);
	updatePacketsData(flowContext.packet, *pluginData);

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginExportResult PacketStatsPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	const std::size_t packetsTotal 
		= flowRecord.src_packets + flowRecord.dst_packets;
	
	if (packetsTotal <= MIN_FLOW_LENGTH) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	m_fieldHandlers[PacketStatsFields::PPI_PKT_LENGTHS].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_TIMES].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_FLAGS].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_DIRECTIONS].setAsAvailable(flowRecord);

	return {
		.flowAction = FlowAction::NoAction,
	};
}

constexpr static
bool isSequenceOverflowed(const uint32_t currentValue, const uint32_t prevValue)
{
	constexpr int64_t MAX_DIFF = static_cast<int64_t>(
		static_cast<double>(std::numeric_limits<uint32_t>::max()) / 100);

	return static_cast<int64_t>(prevValue) 
		- static_cast<int64_t>(currentValue) > MAX_DIFF
}

static
bool isDuplicate(const Packet& packet, const PacketStatsData& pluginData) noexcept
{
	constexpr std::size_t TCP = 6;
	if (packet.ip_proto != TCP) {
		return false;
	}

	// Current seq <= previous ack?
	const bool suspiciousSequence 
		= packet.tcp_seq <= pluginData.processingState.lastSequence[packet.source_pkt]
			&& !isSequenceOverflowed(packet.tcp_seq, pluginData.processingState.lastSequence[packet.source_pkt]);

	// Current ack <= previous ack?
	const bool suspiciousAcknowledgment 
		= packet.tcp_ack <= pluginData.processingState.lastAcknowledgment[packet.source_pkt]
			&& !isSequenceOverflowed(packet.tcp_ack, pluginData.processingState.lastAcknowledgment[packet.source_pkt]);

	if (suspiciousSequence && suspiciousAcknowledgment 
		&& packet.payload_len == pluginData.processingState.lastLength[packet.source_pkt]
		&& packet.tcp_flags == pluginData.processingState.lastFlags[packet.source_pkt] 
		&& pluginData.lengths.size() != 0) {
		return true;
	}

	return false;
}

void PacketStatsPlugin::updatePacketsData(const Packet& packet, PacketStatsData& pluginData) noexcept
{
	if (m_skipDuplicates && isDuplicate(packet, pluginData)) {
		return;
	}

	pluginData.processingState.lastSequence[packet.source_pkt] = packet.tcp_seq;
	pluginData.processingState.lastAcknowledgment[packet.source_pkt] = packet.tcp_ack;
	pluginData.processingState.lastLength[packet.source_pkt] = packet.payload_len;
	pluginData.processingState.lastFlags[packet.source_pkt] = TcpFlags(packet.tcp_flags);

	if (packet.packet_len == 0 && !m_countEmptyPackets) {
		return;
	}

	if (pluginData.lengths.size() == pluginData.lengths.capacity()) {
		return;
	}
	
	pluginData.lengths.push_back(static_cast<uint16_t>(packet.payload_len_wire));

	pluginData.tcpFlags.push_back(TcpFlags(packet.tcp_flags));

	pluginData.timestamps.push_back(packet.ts);
	
	/*
	 * direction =  1 iff client -> server
	 * direction = -1 iff server -> client
	 */
	const int8_t direction = packet.source_pkt ? 1 : -1;
	pluginData.directions.push_back(direction);
}

void PacketStatsPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<PacketStatsData*>(pluginContext));
}

PluginDataMemoryLayout DNSSDPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(PacketStatsData),
		.alignment = alignof(PacketStatsData),
	};
}

std::string PacketStatsPlugin::getName() const noexcept
{
	return packetStatsPluginManifest.name;
}

static const PluginRegistrar<PacketStatsPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	packetStatsRegistrar(packetStatsPluginManifest);

} // namespace ipxp
