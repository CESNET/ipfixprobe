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

#include "dnssdGetters.hpp"
#include "dnssdOptionsParser.hpp"

#include <iostream>

#include <dnsParser/dnsParser.hpp>
#include <dnsParser/dnsQueryType.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::dnssd {

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
		schema.addScalarField("DNSSD_QUERIES", getDNSSDQueriesField));

	handlers.insert(
		DNSSDFields::DNSSD_RESPONSES,
		schema.addScalarField("DNSSD_RESPONSES", getDNSSDResponsesField));

	return schema;
}

DNSSDPlugin::DNSSDPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createDNSSDSchema(manager, m_fieldHandlers);
}

OnInitResult DNSSDPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t DNSSD_PORT = 5353;
	if (flowContext.flowRecord.flowKey.srcPort != DNSSD_PORT
		&& flowContext.flowRecord.flowKey.dstPort != DNSSD_PORT) {
		return OnInitResult::Irrelevant;
	}

	auto& dnssdContext = *std::construct_at(reinterpret_cast<DNSSDContext*>(pluginContext));
	const bool isDNSoverTCP = (getLayerView<amon::layers::TCPView>(
								   *flowContext.packetContext.packet,
								   flowContext.packetContext.packet->layout.l4)
								   .has_value());
	if (!parseDNSSD(getPayload(*flowContext.packetContext.packet), isDNSoverTCP, dnssdContext)) {
		return OnInitResult::ConstructedFinal;
	}

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult DNSSDPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& dnssdContext = *reinterpret_cast<DNSSDContext*>(pluginContext);
	const bool isDNSoverTCP = getLayerView<amon::layers::TCPView>(
								  *flowContext.packetContext.packet,
								  flowContext.packetContext.packet->layout.l4)
								  .has_value();
	if (!parseDNSSD(getPayload(*flowContext.packetContext.packet), isDNSoverTCP, dnssdContext)) {
		return OnUpdateResult::Remove;
	}

	return OnUpdateResult::NeedsUpdate;
}

bool DNSSDPlugin::parseAnswer(const DNSRecord& answer, DNSSDContext& pluginData) noexcept
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
	DNSSDContext& dnssdContext) noexcept
{
	DNSParser parser;

	std::function<bool(const DNSQuestion& query)> queryParser = [&](const DNSQuestion& query) {
		dnssdContext.findOrInsert(query.name);
		return false;
	};

	auto answerParser = [&](const DNSRecord& answer) { return parseAnswer(answer, dnssdContext); };

	const bool parsed
		= parser
			  .parse(payload, isDNSOverTCP, queryParser, answerParser, answerParser, answerParser);
	if (!parsed) {
		return false;
	}

	return true;
}

OnExportResult DNSSDPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	auto& dnssdContext = *reinterpret_cast<DNSSDContext*>(pluginContext);

	if (dnssdContext.requests.empty()) {
		return OnExportResult::Remove;
	}

	concatenateRangeTo(
		dnssdContext.requests | std::views::transform([](const DNSSDRecord& record) {
			return record.requestName.toString();
		}),
		dnssdContext.queries,
		';');
	concatenateRangeTo(
		dnssdContext.requests
			| std::views::transform([](const DNSSDRecord& record) { return record.toString(); }),
		dnssdContext.responses,
		';');

	m_fieldHandlers[DNSSDFields::DNSSD_QUERIES].setAsAvailable(flowRecord);
	m_fieldHandlers[DNSSDFields::DNSSD_RESPONSES].setAsAvailable(flowRecord);

	return OnExportResult::NoAction;
}

void DNSSDPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<DNSSDContext*>(pluginContext));
}

PluginDataMemoryLayout DNSSDPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(DNSSDContext),
		.alignment = alignof(DNSSDContext),
	};
}

static const PluginRegistrar<
	DNSSDPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	dnssdRegistrar(dnssdPluginManifest);

} // namespace ipxp::process::dnssd
