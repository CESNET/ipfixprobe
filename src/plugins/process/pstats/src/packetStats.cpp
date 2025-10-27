/**
 * @file
 * @brief Plugin for parsing pstats traffic.
 * @author Tomas Cejka <cejkat@cesnet.cz>
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that calculates packet statistics as flags, acknowledgments, and sequences
 * within flows, stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "packetStats.hpp"

#include "packetStatsGetters.hpp"
#include "packetStatsOptionsParser.hpp"

#include <iostream>

#include <amon/layers/TCP.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp::process::packet_stats {

static const PluginManifest packetStatsPluginManifest = {
	.name = "pstats",
	.description = "Pstats process plugin for computing packet bursts stats.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			PacketStatsOptionsParser parser;
			parser.usage(std::cout);
		},
};

static void createPacketStatsSchema(
	FieldManager& fieldManager,
	FieldHandlers<PacketStatsFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("pstats");

	/*handlers.insert(
		PacketStatsFields::PPI_PKT_LENGTHS,
		schema.addVectorField("PPI_PKT_LENGTHS", getPacketLengthsField));
	handlers.insert(
		PacketStatsFields::PPI_PKT_FLAGS,
		schema.addVectorField("PPI_PKT_FLAGS", getPacketFlagsField));
	handlers.insert(
		PacketStatsFields::PPI_PKT_DIRECTIONS,
		schema.addVectorField("PPI_PKT_DIRECTIONS", getPacketDirectionsField));
	handlers.insert(
		PacketStatsFields::PPI_PKT_TIMES,
		schema.addVectorField("PPI_PKT_TIMES", getPacketTimestampsField));*/
}

PacketStatsPlugin::PacketStatsPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createPacketStatsSchema(manager, m_fieldHandlers);
}

OnInitResult PacketStatsPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto& packetStatsContext
		= *std::construct_at(reinterpret_cast<PacketStatsContext*>(pluginContext));
	updatePacketsData(
		*flowContext.packetContext.packet,
		flowContext.packetDirection,
		packetStatsContext);

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult PacketStatsPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& packetStatsContext
		= *std::construct_at(reinterpret_cast<PacketStatsContext*>(pluginContext));
	updatePacketsData(
		*flowContext.packetContext.packet,
		flowContext.packetDirection,
		packetStatsContext);

	return OnUpdateResult::NeedsUpdate;
}

OnExportResult
PacketStatsPlugin::onExport(const FlowRecord& flowRecord, [[maybe_unused]] void* pluginContext)
{
	const std::size_t packetsTotal = flowRecord.directionalData[Direction::Forward].packets
		+ flowRecord.directionalData[Direction::Reverse].packets;

	const TCPFlags flags = flowRecord.directionalData[Direction::Forward].tcpFlags
		| flowRecord.directionalData[Direction::Reverse].tcpFlags;

	if (packetsTotal <= MIN_FLOW_LENGTH && flags.bitfields.synchronize) {
		return OnExportResult::Remove;
	}

	m_fieldHandlers[PacketStatsFields::PPI_PKT_LENGTHS].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_TIMES].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_FLAGS].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketStatsFields::PPI_PKT_DIRECTIONS].setAsAvailable(flowRecord);

	return OnExportResult::NoAction;
}

constexpr static bool isSequenceOverflowed(const uint32_t currentValue, const uint32_t prevValue)
{
	constexpr int64_t MAX_DIFF
		= static_cast<int64_t>(static_cast<double>(std::numeric_limits<uint32_t>::max()) / 100);

	return static_cast<int64_t>(prevValue) - static_cast<int64_t>(currentValue) > MAX_DIFF;
}

static bool isDuplicate(
	const amon::Packet& packet,
	const amon::layers::TCPView& tcp,
	const Direction direction,
	const std::size_t ipPayloadLength,
	const PacketStatsContext& packetStatsContext) noexcept
{
	// Current seq <= previous ack?
	const bool suspiciousSequence = tcp.header().sequenceNumber
			<= packetStatsContext.processingState.lastSequence[direction]
		&& !isSequenceOverflowed(tcp.header().sequenceNumber,
								 packetStatsContext.processingState.lastSequence[direction]);

	// Current ack <= previous ack?
	const bool suspiciousAcknowledgment = tcp.header().acknowledgeNumber
			<= packetStatsContext.processingState.lastAcknowledgment[direction]
		&& !isSequenceOverflowed(tcp.header().acknowledgeNumber,
								 packetStatsContext.processingState.lastAcknowledgment[direction]);

	if (suspiciousSequence && suspiciousAcknowledgment
		&& packetStatsContext.processingState.currentStorageSize != 0
		&& ipPayloadLength == packetStatsContext.processingState.lastLength[direction]
		&& TCPFlags(tcp.flags()) == packetStatsContext.processingState.lastFlags[direction]) {
		return true;
	}

	return false;
}

void PacketStatsPlugin::updatePacketsData(
	const amon::Packet& packet,
	const Direction direction,
	PacketStatsContext& packetStatsContext) noexcept
{
	auto tcp = getLayerView<amon::layers::TCPView>(packet, packet.layout.l4);
	if (!tcp.has_value()) {
		return;
	}

	const std::optional<std::size_t> ipPayloadLength = getIPPayloadLength(packet);
	if (!ipPayloadLength.has_value()) {
		return;
	}

	if (m_skipDuplicates
		&& isDuplicate(packet, *tcp, direction, *ipPayloadLength, packetStatsContext)) {
		return;
	}

	packetStatsContext.processingState.lastSequence[direction] = tcp->header().sequenceNumber;
	packetStatsContext.processingState.lastAcknowledgment[direction]
		= tcp->header().acknowledgeNumber;
	packetStatsContext.processingState.lastLength[direction] = *ipPayloadLength;
	packetStatsContext.processingState.lastFlags[direction] = TCPFlags(tcp->flags());

	if (*ipPayloadLength == 0 && !m_countEmptyPackets) {
		return;
	}

	if (packetStatsContext.processingState.currentStorageSize == PacketStatsContext::INITIAL_SIZE) {
		packetStatsContext.reserveMaxSize();
	}
	if (packetStatsContext.processingState.currentStorageSize == PacketStatsContext::MAX_SIZE) {
		return;
	}

	std::visit(
		[&](auto& storage) {
			storage->set(
				packetStatsContext.processingState.currentStorageSize++,
				static_cast<uint16_t>(*ipPayloadLength),
				TCPFlags(tcp->flags()),
				packet.timestamp,
				direction ? 1 : -1);
		},
		packetStatsContext.storage);
}

void PacketStatsPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<PacketStatsContext*>(pluginContext));
}

PluginDataMemoryLayout PacketStatsPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(PacketStatsContext),
		.alignment = alignof(PacketStatsContext),
	};
}

static const PluginRegistrar<
	PacketStatsPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	packetStatsRegistrar(packetStatsPluginManifest);

} // namespace ipxp::process::packet_stats
