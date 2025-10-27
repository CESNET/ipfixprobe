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

#include "ssaDetector.hpp"

#include "ssaDetectorGetters.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>

namespace ipxp::process::ssaDetector {

static const PluginManifest ssaDetectorPluginManifest = {
	.name = "ssadetector",
	.description = "Ssadetector process plugin for parsing vpn_automaton traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser(
				"ssadetector",
				"Check traffic for SYN-SYNACK-ACK sequence to find possible network tunnels.");
			parser.usage(std::cout);
		},
};

static FieldGroup createSSADetectorSchema(
	FieldManager& fieldManager,
	FieldHandlers<SSADetectorFields> handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("ssadetector");

	handlers.insert(
		SSADetectorFields::SSA_CONF_LEVEL,
		schema.addScalarField("SSA_CONF_LEVEL", getSSAConfLevelField));
	return schema;
}

SSADetectorPlugin::SSADetectorPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createSSADetectorSchema(manager, m_fieldHandlers);
}

void SSADetectorPlugin::updatePacketsData(
	const amon::Packet& packet,
	const Direction direction,
	SSADetectorContext& ssaContext) noexcept
{
	const std::optional<std::size_t> ipPayloadLength = getIPPayloadLength(packet);

	if (!ipPayloadLength.has_value() || !PacketStorage::isValid(*ipPayloadLength)) {
		return;
	}

	constexpr std::size_t MaxSynToSynAckSizeDiff = 12;
	const bool foundTCPHandshake
		= ssaContext.processingState.synAckPackets.hasSimilarPacketsRecently(
			*ipPayloadLength,
			MaxSynToSynAckSizeDiff,
			packet.timestamp,
			static_cast<Direction>(!direction));

	if (foundTCPHandshake) {
		ssaContext.processingState.synPackets.clear();
		ssaContext.processingState.synAckPackets.clear();
		ssaContext.processingState.suspects++;
		if (ssaContext.processingState.suspectLengths.size()
			!= ssaContext.processingState.suspectLengths.capacity()) {
			ssaContext.processingState.suspectLengths.push_back(*ipPayloadLength);
		}
		return;
	}

	constexpr std::size_t MaxSynAckToSynSizeDiff = 10;
	const bool correspondingSynFound
		= ssaContext.processingState.synPackets.hasSimilarPacketsRecently(
			*ipPayloadLength,
			MaxSynAckToSynSizeDiff,
			packet.timestamp,
			static_cast<Direction>(!direction));
	if (correspondingSynFound) {
		ssaContext.processingState.synAckPackets.insert(
			*ipPayloadLength,
			packet.timestamp,
			direction);
	}

	ssaContext.processingState.synPackets.insert(*ipPayloadLength, packet.timestamp, direction);
}

OnInitResult SSADetectorPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr std::size_t MIN_FLOW_LENGTH = 30;
	if (flowContext.flowRecord.directionalData[Direction::Forward].packets
			+ flowContext.flowRecord.directionalData[Direction::Reverse].packets
		< MIN_FLOW_LENGTH) {
		return OnInitResult::PendingConstruction;
	}

	auto& ssaContext = *std::construct_at(reinterpret_cast<SSADetectorContext*>(pluginContext));
	updatePacketsData(*flowContext.packetContext.packet, flowContext.packetDirection, ssaContext);

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult SSADetectorPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& ssaContext = *reinterpret_cast<SSADetectorContext*>(pluginContext);
	updatePacketsData(*flowContext.packetContext.packet, flowContext.packetDirection, ssaContext);

	return OnUpdateResult::NeedsUpdate;
}

constexpr static double calculateUniqueRatio(auto&& container) noexcept
{
	std::sort(container.begin(), container.end());
	auto last = std::unique(container.begin(), container.end());
	return static_cast<double>(std::distance(container.begin(), last)) / container.size();
}

OnExportResult SSADetectorPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	auto& ssaContext = *reinterpret_cast<SSADetectorContext*>(pluginContext);
	// do not export for small packets flows
	constexpr double HIGH_NUM_SUSPECTS_MAX_RATIO = 0.2;

	const std::size_t packetsTotal = flowRecord.directionalData[Direction::Forward].packets
		+ flowRecord.directionalData[Direction::Reverse].packets;
	constexpr std::size_t MIN_PACKETS = 30;
	if (packetsTotal <= MIN_PACKETS) {
		return OnExportResult::Remove;
	}

	constexpr std::size_t MIN_SUSPECTS_COUNT = 3;
	if (ssaContext.processingState.suspects < MIN_SUSPECTS_COUNT) {
		return OnExportResult::Remove;
	}

	constexpr std::size_t MIN_SUSPECTS_RATIO = 2500;
	if (double(packetsTotal) / double(ssaContext.processingState.suspects) > MIN_SUSPECTS_RATIO) {
		return OnExportResult::Remove;
	}

	const double uniqueRatio = calculateUniqueRatio(ssaContext.processingState.suspectLengths);
	constexpr std::size_t LOW_NUM_SUSPECTS_THRESHOLD = 15;
	constexpr double LOW_NUM_SUSPECTS_MAX_RATIO = 0.6;
	if (ssaContext.processingState.suspects < LOW_NUM_SUSPECTS_THRESHOLD
		&& uniqueRatio > LOW_NUM_SUSPECTS_MAX_RATIO) {
		return OnExportResult::Remove;
	}

	constexpr std::size_t MID_NUM_SUSPECTS_THRESHOLD = 40;
	constexpr double MID_NUM_SUSPECTS_MAX_RATIO = 0.4;
	if (ssaContext.processingState.suspects < MID_NUM_SUSPECTS_THRESHOLD
		&& uniqueRatio > MID_NUM_SUSPECTS_MAX_RATIO) {
		return OnExportResult::Remove;
	}

	if (uniqueRatio > HIGH_NUM_SUSPECTS_MAX_RATIO) {
		return OnExportResult::Remove;
	}

	ssaContext.confidence = 1;
	m_fieldHandlers[SSADetectorFields::SSA_CONF_LEVEL].setAsAvailable(flowRecord);
	return OnExportResult::NoAction;
}

void SSADetectorPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<SSADetectorContext*>(pluginContext));
}

PluginDataMemoryLayout SSADetectorPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(SSADetectorContext),
		.alignment = alignof(SSADetectorContext),
	};
}

static const PluginRegistrar<
	SSADetectorPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ssaDetectorRegistrar(ssaDetectorPluginManifest);

} // namespace ipxp::process::ssaDetector
