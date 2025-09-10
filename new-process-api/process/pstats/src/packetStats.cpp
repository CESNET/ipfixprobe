/**
 * @file
 * @brief Plugin for parsing pstats traffic.
 * @author Tomas Cejka <cejkat@cesnet.cz>
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that calculates packet statistics as flags, acknowledgments, and sequences within flows,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "packetStats.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>

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

static void createPacketStatsSchema(FieldManager& fieldManager, FieldHandlers<PacketStatsFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("pstats");

	handlers.insert(PacketStatsFields::PPI_PKT_LENGTHS, schema.addVectorField(
		"PPI_PKT_LENGTHS",
		[](const void* context) {
			return toSpan<const uint16_t>(reinterpret_cast<const PacketStatsData*>(context)->lengths);
		}));
	handlers.insert(PacketStatsFields::PPI_PKT_FLAGS, schema.addVectorField(
		"PPI_PKT_FLAGS",
		[](const void* context) {
			return toSpan<const uint8_t>(reinterpret_cast<const PacketStatsData*>(context)->tcpFlags);
	}));
	handlers.insert(PacketStatsFields::PPI_PKT_DIRECTIONS, schema.addVectorField(
		"PPI_PKT_DIRECTIONS",
		[](const void* context) { 
			return toSpan<const uint8_t>(reinterpret_cast<const PacketStatsData*>(context)->directions);
	}));
	handlers.insert(PacketStatsFields::PPI_PKT_TIMES, schema.addVectorField(
		"PPI_PKT_TIMES",
		[](const void* context) {
			return toSpan<const Timestamp>(reinterpret_cast<const PacketStatsData*>(context)->timestamps);
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
		= flowRecord.directionalData[Direction::Forward].packets + 
		flowRecord.directionalData[Direction::Reverse].packets;
	
	const TCPFlags flags = flowRecord.directionalData[Direction::Forward].tcpFlags | 
		flowRecord.directionalData[Direction::Reverse].tcpFlags;
	
	if (packetsTotal <= MIN_FLOW_LENGTH && flags.bitfields.synchronize) {
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
		- static_cast<int64_t>(currentValue) > MAX_DIFF;
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
		&& TCPFlags(packet.tcp_flags) == pluginData.processingState.lastFlags[packet.source_pkt] 
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
	pluginData.processingState.lastFlags[packet.source_pkt] = TCPFlags(packet.tcp_flags);

	if (packet.packet_len == 0 && !m_countEmptyPackets) {
		return;
	}

	if (pluginData.lengths.size() == PacketStatsData::INITIAL_SIZE) {
		pluginData.reserveMaxSize();
	}
	if (pluginData.lengths.size() == PacketStatsData::MAX_SIZE) {
		return;
	}
	
	const int8_t direction = packet.source_pkt ? 1 : -1;
	pluginData.directions.push_back(direction);
	pluginData.lengths.push_back(static_cast<uint16_t>(packet.payload_len_wire));
	pluginData.tcpFlags.push_back(TCPFlags(packet.tcp_flags));
	pluginData.timestamps.push_back(packet.ts);
}

void PacketStatsPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<PacketStatsData*>(pluginContext));
}

PluginDataMemoryLayout PacketStatsPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(PacketStatsData),
		.alignment = alignof(PacketStatsData),
	};
}

static const PluginRegistrar<PacketStatsPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	packetStatsRegistrar(packetStatsPluginManifest);

} // namespace ipxp
