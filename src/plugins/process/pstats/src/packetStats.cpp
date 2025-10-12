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

#include "packetStatsOptionsParser.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
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
			PacketStatsOptionsParser parser;
			parser.usage(std::cout);
		},
};

static void createPacketStatsSchema(
	FieldManager& fieldManager,
	FieldHandlers<PacketStatsFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("pstats");

	// TODO FIX
	/*handlers.insert(PacketStatsFields::PPI_PKT_LENGTHS, schema.addVectorField(
		"PPI_PKT_LENGTHS",
		[](const void* context) {
			return toSpan<const uint16_t>(reinterpret_cast<const
	PacketStatsData*>(context)->lengths);
		}));
	handlers.insert(PacketStatsFields::PPI_PKT_FLAGS, schema.addVectorField(
		"PPI_PKT_FLAGS",
		[](const void* context) {
			return toSpan<const uint8_t>(reinterpret_cast<const
	PacketStatsData*>(context)->tcpFlags);
	}));
	handlers.insert(PacketStatsFields::PPI_PKT_DIRECTIONS, schema.addVectorField(
		"PPI_PKT_DIRECTIONS",
		[](const void* context) {
			return toSpan<const uint8_t>(reinterpret_cast<const
	PacketStatsData*>(context)->directions);
	}));
	handlers.insert(PacketStatsFields::PPI_PKT_TIMES, schema.addVectorField(
		"PPI_PKT_TIMES",
		[](const void* context) {
			return toSpan<const Timestamp>(reinterpret_cast<const
	PacketStatsData*>(context)->timestamps);
	}));*/
}

PacketStatsPlugin::PacketStatsPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createPacketStatsSchema(manager, m_fieldHandlers);
}

PluginInitResult PacketStatsPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<PacketStatsData*>(pluginContext));
	updatePacketsData(flowContext.packet, flowContext.features, *pluginData);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult PacketStatsPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<PacketStatsData*>(pluginContext);
	updatePacketsData(flowContext.packet, flowContext.features, *pluginData);

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginExportResult
PacketStatsPlugin::onExport(const FlowRecord& flowRecord, [[maybe_unused]] void* pluginContext)
{
	const std::size_t packetsTotal = flowRecord.directionalData[Direction::Forward].packets
		+ flowRecord.directionalData[Direction::Reverse].packets;

	const TCPFlags flags = flowRecord.directionalData[Direction::Forward].tcpFlags
		| flowRecord.directionalData[Direction::Reverse].tcpFlags;

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

constexpr static bool isSequenceOverflowed(const uint32_t currentValue, const uint32_t prevValue)
{
	constexpr int64_t MAX_DIFF
		= static_cast<int64_t>(static_cast<double>(std::numeric_limits<uint32_t>::max()) / 100);

	return static_cast<int64_t>(prevValue) - static_cast<int64_t>(currentValue) > MAX_DIFF;
}

static bool isDuplicate(
	const amon::Packet& packet,
	const PacketFeatures& features,
	const PacketStatsData& pluginData) noexcept
{
	if (features.tcp.has_value()) {
		return false;
	}

	// Current seq <= previous ack?
	const bool suspiciousSequence = features.tcpSequence
			<= pluginData.processingState.lastSequence[features.direction]
		&& !isSequenceOverflowed(features.tcpSequence,
								 pluginData.processingState.lastSequence[features.direction]);

	// Current ack <= previous ack?
	const bool suspiciousAcknowledgment = features.tcpAcknowledgment
			<= pluginData.processingState.lastAcknowledgment[features.direction]
		&& !isSequenceOverflowed(features.tcpAcknowledgment,
								 pluginData.processingState.lastAcknowledgment[features.direction]);

	if (suspiciousSequence && suspiciousAcknowledgment
		&& pluginData.processingState.currentStorageSize != 0
		&& features.ipPayloadLength == pluginData.processingState.lastLength[features.direction]
		&& TCPFlags(features.tcp->flags())
			== pluginData.processingState.lastFlags[features.direction]) {
		return true;
	}

	return false;
}

void PacketStatsPlugin::updatePacketsData(
	const amon::Packet& packet,
	const PacketFeatures& features,
	PacketStatsData& pluginData) noexcept
{
	if (m_skipDuplicates && isDuplicate(packet, features, pluginData)) {
		return;
	}

	pluginData.processingState.lastSequence[features.direction] = features.tcpSequence;
	pluginData.processingState.lastAcknowledgment[features.direction] = features.tcpAcknowledgment;
	pluginData.processingState.lastLength[features.direction] = features.ipPayloadLength;
	pluginData.processingState.lastFlags[features.direction] = TCPFlags(features.tcp->flags());

	if (features.ipPayloadLength == 0 && !m_countEmptyPackets) {
		return;
	}

	if (pluginData.processingState.currentStorageSize == PacketStatsData::INITIAL_SIZE) {
		pluginData.reserveMaxSize();
	}
	if (pluginData.processingState.currentStorageSize == PacketStatsData::MAX_SIZE) {
		return;
	}

	std::visit(
		[&](auto& storage) {
			storage->set(
				pluginData.processingState.currentStorageSize++,
				static_cast<uint16_t>(features.ipPayloadLength),
				TCPFlags(features.tcp->flags()),
				packet.timestamp,
				features.direction ? 1 : -1);
		},
		pluginData.storage);
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

static const PluginRegistrar<
	PacketStatsPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	packetStatsRegistrar(packetStatsPluginManifest);

} // namespace ipxp
