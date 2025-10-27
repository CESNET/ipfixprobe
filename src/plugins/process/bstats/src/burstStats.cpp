/**
 * @file
 * @brief Plugin for parsing bstats traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts packet burst statistics of flows,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "burstStats.hpp"

#include "burstStatsContext.hpp"
#include "burstStatsGetters.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp::process::burstStats {

static const PluginManifest burstStatsPluginManifest = {
	.name = "bstats",
	.description = "Bstats process plugin for computing packet bursts stats.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("bstats", "Compute packet bursts stats");
			parser.usage(std::cout);
		},
};

static FieldGroup
createBurstStatsSchema(FieldManager& fieldManager, FieldHandlers<BurstStatsFields>& handlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("bstats");

	auto [sourcePacketsField, destPacketsField] = schema.addVectorDirectionalFields(
		"SBI_BRST_PACKETS",
		"DBI_BRST_PACKETS",
		[](const void* context) { return getBurstPacketsField(context, Direction::Forward); },
		[](const void* context) { return getBurstPacketsField(context, Direction::Reverse); });
	handlers.insert(BurstStatsFields::SBI_BRST_PACKETS, sourcePacketsField);
	handlers.insert(BurstStatsFields::DBI_BRST_PACKETS, destPacketsField);

	auto [sourceBytesField, destBytesField] = schema.addVectorDirectionalFields(
		"SBI_BRST_BYTES",
		"DBI_BRST_BYTES",
		[](const void* context) { return getBurstBytesField(context, Direction::Forward); },
		[](const void* context) { return getBurstBytesField(context, Direction::Reverse); });
	handlers.insert(BurstStatsFields::SBI_BRST_BYTES, sourceBytesField);
	handlers.insert(BurstStatsFields::DBI_BRST_BYTES, destBytesField);

	auto [sourceTimeStartField, destTimeStartField] = schema.addVectorDirectionalFields(
		"SBI_BRST_TIME_START",
		"DBI_BRST_TIME_START",
		[](const void* context) {
			return getBurstStartTimestampsField(context, Direction::Forward);
		},
		[](const void* context) {
			return getBurstStartTimestampsField(context, Direction::Reverse);
		});
	handlers.insert(BurstStatsFields::SBI_BRST_TIME_START, sourceTimeStartField);
	handlers.insert(BurstStatsFields::DBI_BRST_TIME_START, destTimeStartField);

	auto [sourceTimeStopField, destTimeStopField] = schema.addVectorDirectionalFields(
		"SBI_BRST_TIME_STOP",
		"DBI_BRST_TIME_STOP",
		[](const void* context) { return getBurstEndTimestampsField(context, Direction::Forward); },
		[](const void* context) {
			return getBurstEndTimestampsField(context, Direction::Reverse);
		});
	handlers.insert(BurstStatsFields::SBI_BRST_TIME_STOP, sourceTimeStopField);
	handlers.insert(BurstStatsFields::DBI_BRST_TIME_STOP, destTimeStopField);

	return schema;
}

BurstStatsPlugin::BurstStatsPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createBurstStatsSchema(manager, m_fieldHandlers);
}

OnInitResult BurstStatsPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto& burstStatsContext
		= *std::construct_at(reinterpret_cast<BurstStatsContext*>(pluginContext));

	std::optional<Burst> burst = burstStatsContext.push(Direction::Forward);
	updateBursts(*burst, *flowContext.packetContext.packet, *flowContext.packetContext.features);

	return OnInitResult::ConstructedNeedsUpdate;
}

void BurstStatsPlugin::updateBursts(
	Burst& burst,
	const amon::Packet& packet,
	const PacketFeatures& features) noexcept
{
	const std::optional<std::size_t> ipPayloadLength = getIPPayloadLength(packet);
	if (!ipPayloadLength.has_value()) {
		return;
	}

	burst.packets++;
	burst.bytes += *ipPayloadLength;
	burst.end.get() = packet.timestamp;
	if (burst.packets == 1) {
		burst.start.get() = packet.timestamp;
	}
}

OnUpdateResult BurstStatsPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& burstStatsContext = *reinterpret_cast<BurstStatsContext*>(pluginContext);

	std::optional<Burst> burst = burstStatsContext.back(flowContext.packetDirection);
	if (!burst.has_value() || !burst->belongs(flowContext.packetContext.packet->timestamp)) {
		burst = burstStatsContext.push(flowContext.packetDirection);
		if (!burst.has_value()) {
			return OnUpdateResult::Final;
		}
	}

	updateBursts(*burst, *flowContext.packetContext.packet, *flowContext.packetContext.features);

	return OnUpdateResult::NeedsUpdate;
}

OnExportResult
BurstStatsPlugin::onExport(const FlowRecord& flowRecord, [[maybe_unused]] void* pluginContext)
{
	const uint32_t packetsTotal = static_cast<uint32_t>(
		flowRecord.directionalData[Direction::Forward].packets
		+ flowRecord.directionalData[Direction::Reverse].packets);
	if (packetsTotal <= MINIMAL_PACKETS_COUNT) {
		return OnExportResult::Remove;
	}

	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_PACKETS].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_BYTES].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_TIME_START].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_TIME_STOP].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_PACKETS].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_BYTES].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_TIME_START].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_TIME_STOP].setAsAvailable(flowRecord);

	return OnExportResult::NoAction;
}

void BurstStatsPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<BurstStatsContext*>(pluginContext));
}

PluginDataMemoryLayout BurstStatsPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(BurstStatsContext),
		.alignment = alignof(BurstStatsContext),
	};
}

static const PluginRegistrar<BurstStatsPlugin, ProcessPluginFactory>
	burstStatsRegistrar(burstStatsPluginManifest);

} // namespace ipxp::process::burstStats
