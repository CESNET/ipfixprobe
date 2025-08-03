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

#include "packetHistogram.hpp"

#include <iostream>
#include <array>
#include <bit>
#include <algorithm>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

namespace ipxp {

static const PluginManifest packetHistogramPluginManifest = {
	.name = "phists",
	.description = "Phists process plugin for parsing phists traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*PHISTSOptParser parser;
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<PacketHistogramFields>> fields = {
	{PacketHistogramFields::S_PHISTS_SIZES, "S_PHISTS_SIZES"},
	{PacketHistogramFields::S_PHISTS_IPT, "S_PHISTS_IPT"},
	{PacketHistogramFields::D_PHISTS_SIZES, "D_PHISTS_SIZES"},
	{PacketHistogramFields::D_PHISTS_IPT, "D_PHISTS_IPT"},
};


static FieldSchema createPacketHistogramSchema()
{
	FieldSchema schema("phists");

	schema.addVectorField<uint32_t>(
		"S_PHISTS_SIZES",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return getSpan(reinterpret_cast<const PacketHistogramExport*>(thisPtr)
				->packetLengths[Direction::Forward]);
		});

	schema.addVectorField<uint32_t>(
		"S_PHISTS_IPT",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return getSpan(reinterpret_cast<const PacketHistogramExport*>(thisPtr)
				->packetTimediffs[Direction::Forward]);
		});

	schema.addVectorField<uint32_t>(
		"D_PHISTS_SIZES",
		FieldDirection::Reverse,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return getSpan(reinterpret_cast<const PacketHistogramExport*>(thisPtr)
				->packetLengths[Direction::Reverse]);
		});

	schema.addVectorField<uint32_t>(
		"D_PHISTS_IPT",
		FieldDirection::Reverse,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return getSpan(reinterpret_cast<const PacketHistogramExport*>(thisPtr)
				->packetTimediffs[Direction::Reverse]);
		});

	schema.addBiflowPair("S_PHISTS_SIZES", "D_PHISTS_SIZES");
	schema.addBiflowPair("S_PHISTS_IPT", "D_PHISTS_IPT");

	return schema;
}

PacketHistogramPlugin::PacketHistogramPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createPacketHistogramSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	// TODO PARSER

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

constexpr static
uint32_t fastlog2(const uint32_t value)
{
	constexpr auto lookup
	= std::to_array<uint32_t>({0, 9,  1,  10, 13, 21, 2,  29, 11, 14, 16, 18, 22, 25, 3, 30,
	   8, 12, 20, 28, 15, 17, 24, 7,  19, 27, 23, 6,  26, 5,  4, 31});
	
	// Set all bits after highest to 1
	const uint32_t filledValue = std::bit_ceil(value) - 1;

	return lookup[(filledValue * 0x07C4ACDD) >> 27];
}

constexpr static void incrementWithoutOverflow(uint32_t& valueToIncrement) noexcept
{
	uint32_t valueBeforeIncrement{valueToIncrement};
	if (__builtin_add_overflow(valueBeforeIncrement, 1, &valueToIncrement)) {
		// overflow occurred
		valueToIncrement = valueBeforeIncrement;
	}
}

/*
 * 0-15     1. bin
 * 16-31    2. bin
 * 32-63    3. bin
 * 64-127   4. bin
 * 128-255  5. bin
 * 256-511  6. bin
 * 512-1023 7. bin
 * 1024 >   8. bin
 */
constexpr static
void updateHistogram(const uint32_t value, 
	std::array<uint32_t, PacketHistogramExport::HISTOGRAM_SIZE>& histogram) noexcept
{
	// first bin starts on 2^4, -1 for indexing from 0
	constexpr std::size_t firstBinOffset = 3;
	const std::size_t binIndex 
		= std::clamp<uint32_t>(fastlog2(value), firstBinOffset, 
			histogram.size() - 1 + firstBinOffset) - firstBinOffset;
	incrementWithoutOverflow(histogram[binIndex]);
}

void PacketHistogramPlugin::updateExportData(const std::size_t realPacketLength, const uint64_t packetTimestamp, const Direction direction) noexcept
{
	if (realPacketLength == 0 && !m_countEmptyPackets) {
		return;
	}

	updateHistogram(static_cast<uint32_t>(realPacketLength), m_exportData.packetLengths[direction]);

	if (!m_lastTimestamps[direction].has_value()) {
		m_lastTimestamps[direction] = packetTimestamp;
		return;
	}

	const int64_t timediff = std::max<int64_t>(0, static_cast<int64_t>(
		packetTimestamp - *m_lastTimestamps[direction]));
	m_lastTimestamps[direction] = packetTimestamp;
	updateHistogram(static_cast<uint32_t>(timediff), m_exportData.packetTimediffs[direction]);
}

FlowAction PacketHistogramPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord,
	 const Packet& packet)
{
	updateExportData(packet.realLength, packet.timestamp, Direction::Forward);

	return FlowAction::RequestTrimmedData;
}

FlowAction PacketHistogramPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord,
	const Packet& packet)
{
	updateExportData(packet.realLength, packet.timestamp, packet.direction);

	return FlowAction::RequestTrimmedData;
}

void PacketHistogramPlugin::onFlowExport(FlowRecord& flowRecord) {
	constexpr std::size_t MIN_FLOW_LENGTH = 1;
	const std::size_t packetsTotal = flowRecord.dataForward.packets + flowRecord.dataReverse.packets;
	const TcpFlags tcpFlags = flowRecord.dataForward.tcpFlags | flowRecord.dataReverse.tcpFlags;

	// do not export phists for single packets flows, usually port scans
	if (packetsTotal <= MIN_FLOW_LENGTH && (tcpFlags.bitfields.synchronize)) { // tcp SYN set
		return;
	}

	m_fieldHandlers[PacketHistogramFields::S_PHISTS_SIZES].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketHistogramFields::S_PHISTS_IPT].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketHistogramFields::D_PHISTS_SIZES].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketHistogramFields::D_PHISTS_IPT].setAsAvailable(flowRecord);
}

ProcessPlugin* PacketHistogramPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<PacketHistogramPlugin*>(constructAtAddress), *this);
}

std::string PacketHistogramPlugin::getName() const {
	return packetHistogramPluginManifest.name;
}

const void* PacketHistogramPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<PacketHistogramPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	packetHistogramRegistrar(packetHistogramPluginManifest);

} // namespace ipxp
