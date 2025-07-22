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

#include "burstStats.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <packetOfFlowData.hpp>

namespace ipxp {


static const PluginManifest burstStatsPluginManifest = {
	.name = "bstats",
	.description = "Bstats process plugin for computing packet bursts stats.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("bstats", "Compute packet bursts stats");
			parser.usage(std::cout);*/
		},
};

static const PluginRegistrar<BurstStatsPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	burstStatsRegistrar(burstStatsPluginManifest);


const inline std::vector<FieldPair<BurstStatsFields>> fields = {
	{BurstStatsFields::SBI_BRST_PACKETS, "SBI_BRST_PACKETS"},
	{BurstStatsFields::DBI_BRST_PACKETS, "DBI_BRST_PACKETS"},
	{BurstStatsFields::SBI_BRST_BYTES, "SBI_BRST_BYTES"},
	{BurstStatsFields::DBI_BRST_BYTES, "DBI_BRST_BYTES"},
	{BurstStatsFields::SBI_BRST_TIME_START, "SBI_BRST_TIME_START"},
	{BurstStatsFields::DBI_BRST_TIME_START, "DBI_BRST_TIME_START"},
	{BurstStatsFields::SBI_BRST_TIME_STOP, "SBI_BRST_TIME_STOP"},
	{BurstStatsFields::DBI_BRST_TIME_STOP, "DBI_BRST_TIME_STOP"},
};


static FieldSchema createBurstStatsSchema()
{
	FieldSchema schema("bstats");

	schema.addVectorField<uint32_t>(
		"SBI_BRST_PACKETS",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addVectorField<uint32_t>(
		"SBI_BRST_BYTES",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addVectorField<uint32_t>(
		"SBI_BRST_TIME_START",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addVectorField<uint32_t>(
		"SBI_BRST_TIME_STOP",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addVectorField<uint32_t>(
		"DBI_BRST_PACKETS",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addVectorField<uint32_t>(
		"DBI_BRST_BYTES",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addVectorField<uint32_t>(
		"DBI_BRST_TIME_START",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addVectorField<uint32_t>(
		"DBI_BRST_TIME_STOP",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addBiflowPair("SBI_BRST_PACKETS", "DBI_BRST_PACKETS");
	schema.addBiflowPair("SBI_BRST_BYTES", "DBI_BRST_BYTES");
	schema.addBiflowPair("SBI_BRST_TIME_START", "DBI_BRST_TIME_START");
	schema.addBiflowPair("SBI_BRST_TIME_STOP", "DBI_BRST_TIME_STOP");

	return schema;
}

BurstStatsPlugin::BurstStatsPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createBurstStatsSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction BurstStatsPlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{
	std::optional<Burst> burst = m_exportData.push(Direction::Forward);

	if (!burst.has_value()) {
		return FlowAction::RequestNoData;
	}

	updateBursts(*burst, flowRecord, packet, Direction::Forward);

	return FlowAction::RequestTrimmedData;
}

void BurstStatsPlugin::updateBursts(Burst& burst, FlowRecord& flowRecord,
	const Packet& packet) noexcept
{
	constexpr static DirectionalField<BurstStatsFields> packetFields{ipxp::BurstStatsFields::SBI_BRST_PACKETS, ipxp::BurstStatsFields::DBI_BRST_PACKETS};
	constexpr static DirectionalField<BurstStatsFields> byteFields{ipxp::BurstStatsFields::SBI_BRST_BYTES, ipxp::BurstStatsFields::DBI_BRST_BYTES};
	constexpr static DirectionalField<BurstStatsFields> startFields{ipxp::BurstStatsFields::SBI_BRST_TIME_START, ipxp::BurstStatsFields::DBI_BRST_TIME_START};
	constexpr static DirectionalField<BurstStatsFields> endFields{ipxp::BurstStatsFields::SBI_BRST_TIME_STOP, ipxp::BurstStatsFields::DBI_BRST_TIME_STOP};

	burst.packets++;
	m_fieldHandlers[packetFields[packet.direction]].setAsAvailable(flowRecord);

	burst.bytes += packet.realLength;	
	m_fieldHandlers[byteFields[packet.direction]].setAsAvailable(flowRecord);

	burst.end = packet.timestamp;
	m_fieldHandlers[endFields[packet.direction]].setAsAvailable(flowRecord);

	if (burst.packets == 1) {
		burst.start = packet.timestamp;
		m_fieldHandlers[startFields[packet.direction]].setAsAvailable(flowRecord);
	}
}


FlowAction BurstStatsPlugin::onFlowUpdate(FlowRecord& flowRecord, 
	const Packet& packet)
{
	std::optional<Burst> burst = m_exportData.back(packet.direction);
	if (!burst.has_value() || !burst->belongs(packet.timestamp)) {
		burst = m_exportData.push(packet.direction)
	}
	if (!burst.has_value()) {
		return FlowAction::RequestNoData;
	}
	
	updateBursts(burst, packet);

	return FlowAction::RequestTrimmedData;
}

void BurstStatsPlugin::makeAllFieldsUnavailable(FlowRecord& flowRecord) noexcept 
{
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_PACKETS].setAsUnavailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_BYTES].setAsUnavailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_TIME_START].setAsUnavailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_TIME_STOP].setAsUnavailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_PACKETS].setAsUnavailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_BYTES].setAsUnavailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_TIME_START].setAsUnavailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_TIME_STOP].setAsUnavailable(flowRecord);

}


void BurstStatsPlugin::onFlowExport(FlowRecord& flowRecord) {
	const uint32_t packets 
		= flowRecord.dataForward.packets + flowRecord.dataReverse.packets;
	if (packets <= MINIMAL_PACKETS_COUNT) {
		makeAllFieldsUnavailable(flowRecord);
		return;
	}
}

ProcessPlugin* BurstStatsPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<BurstStatsPlugin*>(constructAtAddress), *this);
}

std::string BurstStatsPlugin::getName() const { 
	return burstStatsPluginManifest.name; 
}

const void* BurstStatsPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

} // namespace ipxp
