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
#include <fieldSchema.hpp>
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

const inline std::vector<FieldPair<SSADetectorFields>> fields = {
	{SSADetectorFields::SSA_CONF_LEVEL, "SSA_CONF_LEVEL"},
};


static FieldSchema createSSADetectorSchema()
{
	FieldSchema schema("ssadetector");

	schema.addScalarField<uint8_t>(
		"SSA_CONF_LEVEL",
		FieldDirection::DirectionalIndifferent,
		offsetof(SSADetectorExport, confidence));

	return schema;
}

SSADetectorPlugin::SSADetectorPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createSSADetectorSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

constexpr
void SSADetectorPlugin::updatePacketsData(
	const std::size_t length,
	const uint64_t timestamp,
	const Direction direction) noexcept
{
	if (!PacketStorage::isValid(length)) {
		return;
	}

	constexpr std::size_t MaxSynToSynAckSizeDiff = 12;
	const bool foundTCPHandshake = m_synAckPackets.hasSimilarPacketsRecently(
		length, MaxSynToSynAckSizeDiff, timestamp, static_cast<Direction>(!direction));

	if (foundTCPHandshake) {
		m_synPackets.clear();
		m_synAckPackets.clear();
		m_suspects++;
		if (m_suspectLengths.size() != m_suspectLengths.capacity()) {
			m_suspectLengths.push_back(length);
		}
		return;
	}

	constexpr std::size_t MaxSynAckToSynSizeDiff = 10;
	const bool correspondingSynFound = m_synPackets.hasSimilarPacketsRecently(
		length, MaxSynAckToSynSizeDiff, timestamp, static_cast<Direction>(!direction));
	if (correspondingSynFound) {
		m_synAckPackets.insert(length, timestamp, direction);
	}

	m_synPackets.insert(length, timestamp, direction);
}

FlowAction SSADetectorPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	constexpr std::size_t MIN_FLOW_LENGTH = 30;
	if (flowRecord.dataForward.packets + flowRecord.dataReverse.packets < MIN_FLOW_LENGTH) {
		return FlowAction::RequestTrimmedData;
	}

	updatePacketsData(packet.payload.size(), packet.timestamp, packet.direction);

	return FlowAction::RequestTrimmedData;
}

constexpr static
double calculateUniqueRatio(auto&& container) noexcept
{
	std::sort(container.begin(), container.end());
	auto last = std::unique(container.begin(), container.end());
	return static_cast<double>(
		std::distance(container.begin(), last)) / container.size();
}

void SSADetectorPlugin::onFlowExport(FlowRecord& flowRecord) 
{
	// do not export for small packets flows
	constexpr double HIGH_NUM_SUSPECTS_MAX_RATIO = 0.2;

	const std::size_t packetsTotal 
		= flowRecord.dataForward.packets + flowRecord.dataReverse.packets;
	constexpr std::size_t MIN_PACKETS = 30;
	if (packetsTotal <= MIN_PACKETS) {
		return;
	}

	constexpr std::size_t MIN_SUSPECTS_COUNT = 3;
	if (m_suspects < MIN_SUSPECTS_COUNT) {
		return;
	}

	constexpr std::size_t MIN_SUSPECTS_RATIO = 2500;
	if (double(packetsTotal) / double(m_suspects) > MIN_SUSPECTS_RATIO) {
		return;
	}

	const double uniqueRatio = calculateUniqueRatio(m_suspectLengths);
	constexpr std::size_t LOW_NUM_SUSPECTS_THRESHOLD = 15;
	constexpr double LOW_NUM_SUSPECTS_MAX_RATIO = 0.6;
	if (m_suspects < LOW_NUM_SUSPECTS_THRESHOLD 
		&& uniqueRatio > LOW_NUM_SUSPECTS_MAX_RATIO) {
		return;
	}
	
	constexpr std::size_t MID_NUM_SUSPECTS_THRESHOLD = 40;
	constexpr double MID_NUM_SUSPECTS_MAX_RATIO = 0.4;
	if (m_suspects < MID_NUM_SUSPECTS_THRESHOLD 
		&& uniqueRatio > MID_NUM_SUSPECTS_MAX_RATIO) {
		return;
	}

	if (uniqueRatio > HIGH_NUM_SUSPECTS_MAX_RATIO) {
		return;
	}

	m_exportData.confidence = 1;
	m_fieldHandlers[SSADetectorFields::SSA_CONF_LEVEL].setAsAvailable(flowRecord);
}

ProcessPlugin* SSADetectorPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<SSADetectorPlugin*>(constructAtAddress), *this);
}

std::string SSADetectorPlugin::getName() const { 
	return ssaDetectorPluginManifest.name; 
}

const void* SSADetectorPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<SSADetectorPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ssaDetectorRegistrar(ssaDetectorPluginManifest);

} // namespace ipxp
