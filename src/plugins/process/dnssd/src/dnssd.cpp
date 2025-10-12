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

#include "dnssdOptionsParser.hpp"

#include <iostream>

#include <dnsParser/dnsParser.hpp>
#include <dnsParser/dnsQueryType.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp {

static const PluginManifest dnssdPluginManifest = {
	.name = "dnssd",
	.description = "Dnssd process plugin for parsing dnssd traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			DNSSDOptionsParser parser;
			parser.usage(std::cout);
		},
};

static FieldGroup
createDNSSDSchema(FieldManager& fieldManager, FieldHandlers<DNSSDFields>& handlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("dnssd");

	handlers.insert(
		DNSSDFields::DNSSD_QUERIES,
		schema.addScalarField("DNSSD_QUERIES", [](const void* context) {
			return toStringView(static_cast<const DNSSDData*>(context)->queries);
		}));

	handlers.insert(
		DNSSDFields::DNSSD_RESPONSES,
		schema.addScalarField("DNSSD_RESPONSES", [](const void* context) {
			return toStringView(static_cast<const DNSSDData*>(context)->responses);
		}));

	return schema;
}

DNSSDPlugin::DNSSDPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createDNSSDSchema(manager, m_fieldHandlers);
}

PluginInitResult DNSSDPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t DNSSD_PORT = 5353;
	if (flowContext.flowRecord.flowKey.srcPort != DNSSD_PORT
		&& flowContext.flowRecord.flowKey.dstPort != DNSSD_PORT) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<DNSSDData*>(pluginContext));
	// TODO USE VALUES FROM DISSECTOR
	// constexpr std::size_t TCP = 6;
	const bool isDNSoverTCP = (flowContext.features.tcp.has_value());
	if (!parseDNSSD(getPayload(flowContext.packet), isDNSoverTCP, *pluginData)) {
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
	// constexpr std::size_t TCP = 6;
	const bool isDNSoverTCP = (flowContext.features.tcp.has_value());
	if (!parseDNSSD(getPayload(flowContext.packet), isDNSoverTCP, *pluginData)) {
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

bool DNSSDPlugin::parseAnswer(const DNSRecord& answer, DNSSDData& pluginData) noexcept
{
	if (answer.type == DNSQueryType::SRV) {
		DNSSDRecord& record = pluginData.findOrInsert(answer.name);
		const auto srv = std::get<DNSSRVRecord>(*answer.payload.getUnderlyingType());
		record.srvPort = srv.port;
		record.srvTarget = srv.target;
	}

	if (answer.type == DNSQueryType::TXT) {
		const auto txt = std::get<DNSTXTRecord>(*answer.payload.getUnderlyingType());
		auto firstTxtKey = std::string_view(txt.content.data(), txt.content.find('='));
		if (!m_serviceFilter->matches(toStringView(answer.name.toString()), firstTxtKey)) {
			return true;
		}

		DNSSDRecord& record = pluginData.findOrInsert(answer.name);
		record.txtContent.append(txt.content);
		record.txtContent.push_back(':');
	}

	if (answer.type == DNSQueryType::HINFO) {
		DNSSDRecord& record = pluginData.findOrInsert(answer.name);
		const auto hinfo = std::get<DNSHINFORecord>(*answer.payload.getUnderlyingType());
		record.cpu = hinfo.cpu;
		record.operatingSystem = hinfo.operatingSystem;
	}

	return false;
}

bool DNSSDPlugin::parseDNSSD(
	std::span<const std::byte> payload,
	const bool isDNSOverTCP,
	DNSSDData& pluginData) noexcept
{
	DNSParser parser;

	std::function<bool(const DNSQuestion& query)> queryParser = [&](const DNSQuestion& query) {
		pluginData.findOrInsert(query.name);
		return false;
	};

	auto answerParser = [&](const DNSRecord& answer) { return parseAnswer(answer, pluginData); };

	const bool parsed
		= parser
			  .parse(payload, isDNSOverTCP, queryParser, answerParser, answerParser, answerParser);
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

	concatenateRangeTo(
		pluginData.requests | std::views::transform([](const DNSSDRecord& record) {
			return record.requestName.toString();
		}),
		pluginData.queries,
		';');
	concatenateRangeTo(
		pluginData.requests
			| std::views::transform([](const DNSSDRecord& record) { return record.toString(); }),
		pluginData.responses,
		';');

	m_fieldHandlers[DNSSDFields::DNSSD_QUERIES].setAsAvailable(flowRecord);
	m_fieldHandlers[DNSSDFields::DNSSD_RESPONSES].setAsAvailable(flowRecord);

	return {
		.flowAction = FlowAction::NoAction,
	};
}

void DNSSDPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<DNSSDData*>(pluginContext));
}

PluginDataMemoryLayout DNSSDPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(DNSSDData),
		.alignment = alignof(DNSSDData),
	};
}

static const PluginRegistrar<
	DNSSDPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	dnssdRegistrar(dnssdPluginManifest);

} // namespace ipxp
