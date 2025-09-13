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
#include "burstStatsData.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

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

static FieldSchema createBurstStatsSchema(FieldManager& fieldManager, FieldHandlers<BurstStatsFields>& handlers)
{
	FieldSchema schema = fieldManager.createFieldSchema("bstats");

	auto [sourcePacketsField, destPacketsField] = schema.addVectorDirectionalFields(
		"SBI_BRST_PACKETS", "DBI_BRST_PACKETS",
		[](const void* context) { return reinterpret_cast<const BurstStatsData*>(context)->getPackets(Direction::Forward); },
		[](const void* context) { return reinterpret_cast<const BurstStatsData*>(context)->getPackets(Direction::Reverse); }
	);
	handlers.insert(BurstStatsFields::SBI_BRST_PACKETS, sourcePacketsField);
	handlers.insert(BurstStatsFields::DBI_BRST_PACKETS, destPacketsField);

	auto [sourceBytesField, destBytesField] = schema.addVectorDirectionalFields(
		"SBI_BRST_BYTES", "DBI_BRST_BYTES",
		[](const void* context) { return reinterpret_cast<const BurstStatsData*>(context)->getBytes(Direction::Forward); },
		[](const void* context) { return reinterpret_cast<const BurstStatsData*>(context)->getBytes(Direction::Reverse); }
	);
	handlers.insert(BurstStatsFields::SBI_BRST_BYTES, sourceBytesField);
	handlers.insert(BurstStatsFields::DBI_BRST_BYTES, destBytesField);


	auto [sourceTimeStartField, destTimeStartField] = schema.addVectorDirectionalFields(
		"SBI_BRST_TIME_START", "DBI_BRST_TIME_START",
		[](const void* context) { return reinterpret_cast<const BurstStatsData*>(context)->getStartTimestamps(Direction::Forward); },
		[](const void* context) { return reinterpret_cast<const BurstStatsData*>(context)->getStartTimestamps(Direction::Reverse); }
	);
	handlers.insert(BurstStatsFields::SBI_BRST_TIME_START, sourceTimeStartField);
	handlers.insert(BurstStatsFields::DBI_BRST_TIME_START, destTimeStartField);

	auto [sourceTimeStopField, destTimeStopField] = schema.addVectorDirectionalFields(
		"SBI_BRST_TIME_STOP", "DBI_BRST_TIME_STOP",
		[](const void* context) { return reinterpret_cast<const BurstStatsData*>(context)->getEndTimestamps(Direction::Forward); },
		[](const void* context) { return reinterpret_cast<const BurstStatsData*>(context)->getEndTimestamps(Direction::Reverse); }
	);
	handlers.insert(BurstStatsFields::SBI_BRST_TIME_STOP, sourceTimeStopField);
	handlers.insert(BurstStatsFields::DBI_BRST_TIME_STOP, destTimeStopField);

	return schema;
}

BurstStatsPlugin::BurstStatsPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createBurstStatsSchema(manager, m_fieldHandlers);
}

PluginInitResult BurstStatsPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<BurstStatsData*>(pluginContext));
	
	std::optional<Burst> burst = pluginData->push(Direction::Forward);
	updateBursts(*burst, flowContext.flowRecord, flowContext.packet);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

void BurstStatsPlugin::updateBursts(Burst& burst, FlowRecord& flowRecord,
	const Packet& packet) noexcept
{
	burst.packets++;
	burst.bytes += packet.ip_payload_len;	
	burst.end.get() = packet.ts;
	if (burst.packets == 1) {
		burst.start.get() = packet.ts;
	}
}

PluginUpdateResult BurstStatsPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<BurstStatsData*>(pluginContext);

	std::optional<Burst> burst = pluginData->back(flowContext.packet.source_pkt);
	if (!burst.has_value() || !burst->belongs(flowContext.packet.ts)) {
		burst = pluginData->push(flowContext.packet.source_pkt);
	}
	if (!burst.has_value()) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	updateBursts(*burst, flowContext.flowRecord, flowContext.packet);

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginExportResult BurstStatsPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	const uint32_t packetsTotal
		= static_cast<uint32_t>(
			flowRecord.directionalData[Direction::Forward].packets + flowRecord.directionalData[Direction::Reverse].packets);
	if (packetsTotal <= MINIMAL_PACKETS_COUNT) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_PACKETS].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_BYTES].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_TIME_START].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::SBI_BRST_TIME_STOP].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_PACKETS].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_BYTES].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_TIME_START].setAsAvailable(flowRecord);
	m_fieldHandlers[ipxp::BurstStatsFields::DBI_BRST_TIME_STOP].setAsAvailable(flowRecord);

	return {
		.flowAction = FlowAction::NoAction,
	};
}

void BurstStatsPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<BurstStatsData*>(pluginContext));
}

PluginDataMemoryLayout BurstStatsPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(BurstStatsData),
		.alignment = alignof(BurstStatsData),
	};
}

static const PluginRegistrar<BurstStatsPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	burstStatsRegistrar(burstStatsPluginManifest);

} // namespace ipxp
