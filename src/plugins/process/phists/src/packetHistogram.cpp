/**
 * @file
 * @brief Plugin for parsing phists traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that creates histograms based on packet sizes and inter-arrival times,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "packetHistogram.hpp"

#include "packetHistogramGetters.hpp"
#include "packetHistogramOptionsParser.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp::process::packet_histogram {

static const PluginManifest packetHistogramPluginManifest = {
	.name = "phists",
	.description = "Phists process plugin for parsing phists traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			PacketHistogramOptionsParser parser;
			parser.usage(std::cout);
		},
};

static FieldGroup createPacketHistogramSchema(
	FieldManager& fieldManager,
	FieldHandlers<PacketHistogramFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("phists");

	auto [forwardSizesField, reverseSizesField] = schema.addVectorDirectionalFields(
		"S_PHISTS_SIZES",
		"D_PHISTS_SIZES",
		[](const void* context) { return getPacketLengthsField(context, Direction::Forward); },
		[](const void* context) { return getPacketLengthsField(context, Direction::Reverse); });
	handlers.insert(PacketHistogramFields::S_PHISTS_SIZES, forwardSizesField);
	handlers.insert(PacketHistogramFields::D_PHISTS_SIZES, reverseSizesField);

	auto [forwardIPTField, reverseIPTField] = schema.addVectorDirectionalFields(
		"S_PHISTS_IPT",
		"D_PHISTS_IPT",
		[](const void* context) { return getPacketTimediffsField(context, Direction::Forward); },
		[](const void* context) { return getPacketTimediffsField(context, Direction::Reverse); });
	handlers.insert(PacketHistogramFields::S_PHISTS_IPT, forwardIPTField);
	handlers.insert(PacketHistogramFields::D_PHISTS_IPT, reverseIPTField);

	return schema;
}

PacketHistogramPlugin::PacketHistogramPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createPacketHistogramSchema(manager, m_fieldHandlers);
}

constexpr static uint32_t fastlog2(const uint32_t value)
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
	uint32_t valueBeforeIncrement {valueToIncrement};
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
constexpr static void updateHistogram(
	const uint32_t value,
	std::array<uint32_t, PacketHistogramContext::HISTOGRAM_SIZE>& histogram) noexcept
{
	// first bin starts on 2^4, -1 for indexing from 0
	constexpr std::size_t firstBinOffset = 3;
	const std::size_t binIndex = std::clamp<uint32_t>(
									 fastlog2(value),
									 firstBinOffset,
									 histogram.size() - 1 + firstBinOffset)
		- firstBinOffset;
	incrementWithoutOverflow(histogram[binIndex]);
}

void PacketHistogramPlugin::updateExportData(
	const uint16_t realPacketLength,
	const amon::types::Timestamp packetTimestamp,
	const Direction direction,
	PacketHistogramContext& packetHistogramContext) noexcept
{
	if (realPacketLength == 0 && !m_countEmptyPackets) {
		return;
	}

	updateHistogram(
		static_cast<uint32_t>(realPacketLength),
		packetHistogramContext.packetLengths[direction]);

	if (!packetHistogramContext.processingState.lastTimestamps[direction].has_value()) {
		packetHistogramContext.processingState.lastTimestamps[direction]
			= packetTimestamp.nanoseconds();
		return;
	}

	const int64_t timediff = std::max<int64_t>(
		0,
		(packetTimestamp.nanoseconds()
		 - *packetHistogramContext.processingState.lastTimestamps[direction]));
	packetHistogramContext.processingState.lastTimestamps[direction]
		= packetTimestamp.nanoseconds();
	updateHistogram(
		static_cast<uint32_t>(timediff),
		packetHistogramContext.packetTimediffs[direction]);
}

OnInitResult PacketHistogramPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto& packetHistogramContext
		= *std::construct_at(reinterpret_cast<PacketHistogramContext*>(pluginContext));

	const std::optional<std::size_t> realPacketLength
		= getIPPayloadLength(*flowContext.packetContext.packet);
	if (!realPacketLength.has_value()) {
		return OnInitResult::Irrelevant;
	}

	updateExportData(
		*realPacketLength,
		flowContext.packetContext.packet->timestamp,
		Direction::Forward,
		packetHistogramContext);

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult PacketHistogramPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& packetHistogramContext = *reinterpret_cast<PacketHistogramContext*>(pluginContext);

	const std::optional<std::size_t> realPacketLength
		= getIPPayloadLength(*flowContext.packetContext.packet);
	if (!realPacketLength.has_value()) {
		return OnUpdateResult::NeedsUpdate;
	}

	updateExportData(
		*realPacketLength,
		flowContext.packetContext.packet->timestamp,
		flowContext.packetDirection,
		packetHistogramContext);

	return OnUpdateResult::NeedsUpdate;
}

OnExportResult
PacketHistogramPlugin::onExport(const FlowRecord& flowRecord, [[maybe_unused]] void* pluginContext)
{
	const std::size_t packetsTotal = flowRecord.directionalData[Direction::Forward].packets
		+ flowRecord.directionalData[Direction::Reverse].packets;
	const TCPFlags tcpFlags = flowRecord.directionalData[Direction::Forward].tcpFlags
		| flowRecord.directionalData[Direction::Reverse].tcpFlags;

	// do not export phists for single packets flows, usually port scans
	constexpr std::size_t MIN_FLOW_LENGTH = 1;
	if (packetsTotal <= MIN_FLOW_LENGTH && tcpFlags.bitfields.synchronize) {
		return OnExportResult::Remove;
	}

	m_fieldHandlers[PacketHistogramFields::S_PHISTS_SIZES].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketHistogramFields::S_PHISTS_IPT].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketHistogramFields::D_PHISTS_SIZES].setAsAvailable(flowRecord);
	m_fieldHandlers[PacketHistogramFields::D_PHISTS_IPT].setAsAvailable(flowRecord);

	return OnExportResult::NoAction;
}

void PacketHistogramPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<PacketHistogramContext*>(pluginContext));
}

PluginDataMemoryLayout PacketHistogramPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(PacketHistogramContext),
		.alignment = alignof(PacketHistogramContext),
	};
}

static const PluginRegistrar<
	PacketHistogramPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	packetHistogramRegistrar(packetHistogramPluginManifest);

} // namespace ipxp::process::packet_histogram
