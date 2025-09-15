/**
 * @file
 * @brief Plugin for parsing dnssd traffic.
 * @author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts DNS-SD data from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "dnssd.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <dnsParser/dnsParser.hpp>
#include <dnsParser/dnsQueryType.hpp>
#include <utils/stringViewUtils.hpp>
#include <utils/stringUtils.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp {

static const PluginManifest dnssdPluginManifest = {
	.name = "dnssd",
	.description = "Dnssd process plugin for parsing dnssd traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*DNSSDOptParser parser;
			parser.usage(std::cout);*/
		},
};

static FieldSchema createDNSSDSchema(FieldManager& fieldManager, FieldHandlers<DNSSDFields>& handlers)
{
	FieldSchema schema = fieldManager.createFieldSchema("dnssd");

	handlers.insert(DNSSDFields::DNSSD_QUERIES, schema.addScalarField("DNSSD_QUERIES", [](const void* context) {
		return toStringView(static_cast<const DNSSDData*>(context)->queries);
	}));

	handlers.insert(DNSSDFields::DNSSD_RESPONSES, schema.addScalarField("DNSSD_RESPONSES", [](const void* context) {
		return toStringView(static_cast<const DNSSDData*>(context)->responses);
	}));

	return schema;
}

DNSSDPlugin::DNSSDPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createDNSSDSchema(manager, m_fieldHandlers);
}

PluginInitResult DNSSDPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t DNSSD_PORT = 5353;
	if (flowContext.packet.src_port != DNSSD_PORT && 
		flowContext.packet.dst_port != DNSSD_PORT) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<DNSSDData*>(pluginContext));
	// TODO USE VALUES FROM DISSECTOR
	constexpr std::size_t TCP = 6;
	const bool isDNSoverTCP = (flowContext.packet.ip_proto == TCP);
	if (!parseDNSSD(toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len), isDNSoverTCP, flowContext.flowRecord, *pluginData)) {
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult DNSSDPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<DNSSDData*>(pluginContext);
	// TODO USE VALUES FROM DISSECTOR
	constexpr std::size_t TCP = 6;
	const bool isDNSoverTCP = (flowContext.packet.ip_proto == TCP);
	if (!parseDNSSD(toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len), isDNSoverTCP, flowContext.flowRecord, *pluginData)) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

bool DNSSDPlugin::parseDNSSD(
	std::span<const std::byte> payload, 
	const bool isDNSOverTCP,
	FlowRecord& flowRecord,
	DNSSDData& pluginData) noexcept
{
	DNSParser parser;

	std::function<bool(const DNSQuestion& query)>
	queryParser = [&](const DNSQuestion& query) {
		pluginData.findOrInsert(query.name);
		return false;
	};

	auto answerParser = [&](const DNSRecord& answer) {

		if (answer.type == DNSQueryType::SRV) {
			DNSSDRecord& record = pluginData.findOrInsert(answer.name);
			const auto& srv 
				= std::get<DNSSRVRecord>(*answer.payload.getUnderlyingType());
			record.srvPort = srv.port;
			record.srvTarget = srv.target;
		}

		if (answer.type == DNSQueryType::TXT) {
			DNSSDRecord& record = pluginData.findOrInsert(answer.name);
			const auto& txt
				= std::get<DNSTXTRecord>(*answer.payload.getUnderlyingType());
			record.txtContent.push_back(txt.content);
		}

		if (answer.type == DNSQueryType::HINFO) {
			DNSSDRecord& record = pluginData.findOrInsert(answer.name);
			const auto& hinfo
				= std::get<DNSHINFORecord>(*answer.payload.getUnderlyingType());
			record.cpu = hinfo.cpu;
			record.operatingSystem = hinfo.operatingSystem;
		}

		return false;
	};

	const bool parsed = parser.parse(
		payload, isDNSOverTCP, queryParser, answerParser,
		answerParser, answerParser);
	if (!parsed) {
		return false;
	}

	return true;
}

PluginExportResult DNSSDPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	auto pluginData = *reinterpret_cast<DNSSDData*>(pluginContext);

	if (pluginData.requests.empty()) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	concatenateRangeTo(pluginData.requests | std::views::transform([](const DNSSDRecord& record) {
		return record.requestName.toString();
	}), pluginData.queries, ';');
	concatenateRangeTo(pluginData.requests | std::views::transform([](const DNSSDRecord& record) {
		return record.toString();
	}), pluginData.responses, ';');
	
	m_fieldHandlers[DNSSDFields::DNSSD_QUERIES].setAsAvailable(flowRecord);
	m_fieldHandlers[DNSSDFields::DNSSD_RESPONSES].setAsAvailable(flowRecord);

	return {
		.flowAction = FlowAction::NoAction,
	};
}

PluginDataMemoryLayout DNSSDPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(DNSSDData),
		.alignment = alignof(DNSSDData),
	};
}

static const PluginRegistrar<DNSSDPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	dnssdRegistrar(dnssdPluginManifest);

} // namespace ipxp
