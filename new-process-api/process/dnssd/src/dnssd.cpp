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
	if (flowContext.packet.flowKey.srcPort != DNSSD_PORT && 
		flowContext.packet.flowKey.dstPort != DNSSD_PORT) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<DNSSDData*>(pluginContext));
	// TODO USE VALUES FROM DISSECTOR
	constexpr std::size_t TCP = 6;
	const bool isDNSoverTCP = (flowContext.packet.flowKey.l4Protocol == TCP);
	if (!parseDNSSD(flowContext.packet.payload, isDNSoverTCP, flowContext.flowRecord, *pluginData)) {
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
	const bool isDNSoverTCP = (flowContext.packet.flowKey.l4Protocol == TCP);
	if (!parseDNSSD(flowContext.packet.payload, isDNSoverTCP, flowContext.flowRecord, *pluginData)) {
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

	std::ranges::for_each(pluginData.requests, 
		[&](const DNSSDRecord& response) {
			const std::string& name = response.requestName.toString();
			if (name.size() < 
				pluginData.queries.capacity() - pluginData.queries.size()) {
				pluginData.queries.insert(
					pluginData.queries.end(), name.begin(), name.end());
				pluginData.queries.push_back(';');
			}
		});

	std::ranges::for_each(pluginData.requests, 
		[&](const DNSSDRecord& response) {
			const std::string& value = response.toString() + ';';
			std::ranges::copy(value | 
				std::views::take(
					pluginData.responses.capacity() - 
					pluginData.responses.size()),
				std::back_inserter(pluginData.responses));
		});
	
	m_fieldHandlers[DNSSDFields::DNSSD_QUERIES].setAsAvailable(flowRecord);
	m_fieldHandlers[DNSSDFields::DNSSD_RESPONSES].setAsAvailable(flowRecord);

	return {
		.flowAction = FlowAction::NoAction,
	};
}

std::string DNSSDPlugin::getName() const noexcept
{ 
	return dnssdPluginManifest.name; 
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
