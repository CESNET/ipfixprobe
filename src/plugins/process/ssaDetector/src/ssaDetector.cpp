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

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

namespace ipxp {

static const PluginManifest ssaDetectorPluginManifest = {
	.name = "ssadetector",
	.description = "Ssadetector process plugin for parsing vpn_automaton traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser(
				"ssadetector",
				"Check traffic for SYN-SYNACK-ACK sequence to find possible network tunnels.");
			parser.usage(std::cout);*/
		},
};

static FieldGroup createSSADetectorSchema(FieldManager& fieldManager, FieldHandlers<SSADetectorFields> handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("ssadetector");

	handlers.insert(SSADetectorFields::SSA_CONF_LEVEL, schema.addScalarField(
		"SSA_CONF_LEVEL",
		[](const void* context) { return reinterpret_cast<const SSADetectorData*>(context)->confidence; }
	));
	return schema;
}

SSADetectorPlugin::SSADetectorPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createSSADetectorSchema(manager, m_fieldHandlers);
}

constexpr
void SSADetectorPlugin::updatePacketsData(
	const std::size_t length,
	const Timestamp timestamp,
	const Direction direction,
	SSADetectorData& pluginData
) noexcept
{
	if (!PacketStorage::isValid(length)) {
		return;
	}

	constexpr std::size_t MaxSynToSynAckSizeDiff = 12;
	const bool foundTCPHandshake = pluginData.processingState.synAckPackets.hasSimilarPacketsRecently(
		length, MaxSynToSynAckSizeDiff, timestamp, static_cast<Direction>(!direction));

	if (foundTCPHandshake) {
		pluginData.processingState.synPackets.clear();
		pluginData.processingState.synAckPackets.clear();
		pluginData.processingState.suspects++;
		if (pluginData.processingState.suspectLengths.size() != pluginData.processingState.suspectLengths.capacity()) {
			pluginData.processingState.suspectLengths.push_back(length);
		}
		return;
	}

	constexpr std::size_t MaxSynAckToSynSizeDiff = 10;
	const bool correspondingSynFound = pluginData.processingState.synPackets.hasSimilarPacketsRecently(
		length, MaxSynAckToSynSizeDiff, timestamp, static_cast<Direction>(!direction));
	if (correspondingSynFound) {
		pluginData.processingState.synAckPackets.insert(length, timestamp, direction);
	}

	pluginData.processingState.synPackets.insert(length, timestamp, direction);
}


PluginInitResult SSADetectorPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr std::size_t MIN_FLOW_LENGTH = 30;
	if (flowContext.flowRecord.directionalData[Direction::Forward].packets + 
		flowContext.flowRecord.directionalData[Direction::Reverse].packets < MIN_FLOW_LENGTH) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}
	
	auto* pluginData = std::construct_at(reinterpret_cast<SSADetectorData*>(pluginContext));
	updatePacketsData(flowContext.packet.payload_len, flowContext.packet.ts, flowContext.packet.source_pkt, *pluginData);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}


PluginUpdateResult SSADetectorPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<SSADetectorData*>(pluginContext);
	updatePacketsData(flowContext.packet.payload_len, flowContext.packet.ts, flowContext.packet.source_pkt, *pluginData);
	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	}; 
}

constexpr static
double calculateUniqueRatio(auto&& container) noexcept
{
	std::sort(container.begin(), container.end());
	auto last = std::unique(container.begin(), container.end());
	return static_cast<double>(
		std::distance(container.begin(), last)) / container.size();
}

PluginExportResult SSADetectorPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	auto pluginData = *reinterpret_cast<SSADetectorData*>(pluginContext);
	// do not export for small packets flows
	constexpr double HIGH_NUM_SUSPECTS_MAX_RATIO = 0.2;

	const std::size_t packetsTotal 
		= flowRecord.directionalData[Direction::Forward].packets + flowRecord.directionalData[Direction::Reverse].packets;
	constexpr std::size_t MIN_PACKETS = 30;
	if (packetsTotal <= MIN_PACKETS) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	constexpr std::size_t MIN_SUSPECTS_COUNT = 3;
	if (pluginData.processingState.suspects < MIN_SUSPECTS_COUNT) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	constexpr std::size_t MIN_SUSPECTS_RATIO = 2500;
	if (double(packetsTotal) / double(pluginData.processingState.suspects) > MIN_SUSPECTS_RATIO) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	const double uniqueRatio = calculateUniqueRatio(pluginData.processingState.suspectLengths);
	constexpr std::size_t LOW_NUM_SUSPECTS_THRESHOLD = 15;
	constexpr double LOW_NUM_SUSPECTS_MAX_RATIO = 0.6;
	if (pluginData.processingState.suspects < LOW_NUM_SUSPECTS_THRESHOLD 
		&& uniqueRatio > LOW_NUM_SUSPECTS_MAX_RATIO) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}
	
	constexpr std::size_t MID_NUM_SUSPECTS_THRESHOLD = 40;
	constexpr double MID_NUM_SUSPECTS_MAX_RATIO = 0.4;
	if (pluginData.processingState.suspects < MID_NUM_SUSPECTS_THRESHOLD 
		&& uniqueRatio > MID_NUM_SUSPECTS_MAX_RATIO) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	if (uniqueRatio > HIGH_NUM_SUSPECTS_MAX_RATIO) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	pluginData.confidence = 1;
	m_fieldHandlers[SSADetectorFields::SSA_CONF_LEVEL].setAsAvailable(flowRecord);
	return {
		.flowAction = FlowAction::NoAction,
	};
}

void SSADetectorPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<SSADetectorData*>(pluginContext));
}

PluginDataMemoryLayout SSADetectorPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(SSADetectorData),
		.alignment = alignof(SSADetectorData),
	};
}

static const PluginRegistrar<SSADetectorPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ssaDetectorRegistrar(ssaDetectorPluginManifest);

} // namespace ipxp
