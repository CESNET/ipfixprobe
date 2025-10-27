/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts DNS fields from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "dns.hpp"

#include "dnsGetters.hpp"

#include <iostream>

#include <dnsParser/dnsParser.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::dns {

static const PluginManifest dnsPluginManifest = {
	.name = "dns",
	.description = "Dns process plugin for parsing dns traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("dns", "Parse DNS traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createPacketStatsSchema(FieldManager& fieldManager, FieldHandlers<DNSFields>& handlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("dns");

	handlers.insert(DNSFields::DNS_ID, schema.addScalarField("DNS_ID", getDNSIdField));
	handlers.insert(
		DNSFields::DNS_ANSWERS,
		schema.addScalarField("DNS_ANSWERS", getDNSAnswersField));
	handlers.insert(DNSFields::DNS_RCODE, schema.addScalarField("DNS_RCODE", getDNSRcodeField));

	handlers.insert(DNSFields::DNS_NAME, schema.addScalarField("DNS_NAME", getDNSNameField));
	handlers.insert(DNSFields::DNS_QTYPE, schema.addScalarField("DNS_QTYPE", getDNSQTypeField));
	handlers.insert(DNSFields::DNS_CLASS, schema.addScalarField("DNS_CLASS", getDNSClassField));
	handlers.insert(DNSFields::DNS_RR_TTL, schema.addScalarField("DNS_RR_TTL", getDNSRRTTLField));
	handlers.insert(
		DNSFields::DNS_RLENGTH,
		schema.addScalarField("DNS_RLENGTH", getDNSRLenghtField));
	handlers.insert(DNSFields::DNS_RDATA, schema.addScalarField("DNS_RDATA", getDNSRDataField));
	handlers.insert(DNSFields::DNS_PSIZE, schema.addScalarField("DNS_PSIZE", getDNSPSizeField));
	handlers.insert(DNSFields::DNS_DO, schema.addScalarField("DNS_DO", getDNSDoField));

	return schema;
}

DNSPlugin::DNSPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createPacketStatsSchema(manager, m_fieldHandlers);
}

OnInitResult DNSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t DNS_PORT = 53;
	if (flowContext.flowRecord.flowKey.srcPort != DNS_PORT
		&& flowContext.flowRecord.flowKey.dstPort != DNS_PORT) {
		return OnInitResult::Irrelevant;
	}

	auto& dnsContext = *std::construct_at(reinterpret_cast<DNSContext*>(pluginContext));

	const bool isDNSOverTCP = getLayerView<amon::layers::TCPView>(
								  *flowContext.packetContext.packet,
								  flowContext.packetContext.packet->layout.l4)
								  .has_value();
	if (parseDNS(
			getPayload(*flowContext.packetContext.packet),
			isDNSOverTCP,
			flowContext.flowRecord,
			dnsContext)) {
		return OnInitResult::ConstructedFinal;
	}

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult DNSPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& dnsContext = *reinterpret_cast<DNSContext*>(pluginContext);

	const bool isDNSOverTCP = getLayerView<amon::layers::TCPView>(
								  *flowContext.packetContext.packet,
								  flowContext.packetContext.packet->layout.l4)
								  .has_value();
	if (parseDNS(
			getPayload(*flowContext.packetContext.packet),
			isDNSOverTCP,
			flowContext.flowRecord,
			dnsContext)) {
		return OnUpdateResult::FlushFlow;
	}

	return OnUpdateResult::NeedsUpdate;
}

bool DNSPlugin::parseQuery(
	const DNSQuestion& query,
	FlowRecord& flowRecord,
	DNSContext& dnsContext) noexcept
{
	dnsContext.firstQuestionName = query.name.toString();
	m_fieldHandlers[DNSFields::DNS_NAME].setAsAvailable(flowRecord);

	dnsContext.firstQuestionType = query.type;
	m_fieldHandlers[DNSFields::DNS_QTYPE].setAsAvailable(flowRecord);

	dnsContext.firstQuestionClass = query.recordClass;
	m_fieldHandlers[DNSFields::DNS_CLASS].setAsAvailable(flowRecord);

	return true;
}

bool DNSPlugin::parseAnswer(
	const DNSRecord& answer,
	FlowRecord& flowRecord,
	DNSContext& dnsContext) noexcept
{
	dnsContext.firstResponseTimeToLive = answer.timeToLive;
	m_fieldHandlers[DNSFields::DNS_RR_TTL].setAsAvailable(flowRecord);
	const std::optional<DNSRecordPayloadType> firstResponse = answer.payload.getUnderlyingType();
	dnsContext.firstResponseAsString = "";
	if (firstResponse.has_value()) {
		dnsContext.firstResponseAsString
			= std::visit([](const auto& record) { return record.toDNSString(); }, *firstResponse);
	}
	m_fieldHandlers[DNSFields::DNS_RDATA].setAsAvailable(flowRecord);

	dnsContext.firstResponseAsStringLength = dnsContext.firstResponseAsString.size();
	m_fieldHandlers[DNSFields::DNS_RLENGTH].setAsAvailable(flowRecord);

	return true;
}

bool DNSPlugin::parseAdditional(
	const DNSRecord& record,
	FlowRecord& flowRecord,
	DNSContext& dnsContext) noexcept
{
	if (record.type != DNSQueryType::OPT) {
		return false;
	}

	dnsContext.firstOTPPayloadSize = record.recordClass;
	m_fieldHandlers[DNSFields::DNS_PSIZE].setAsAvailable(flowRecord);

	dnsContext.dnssecOkBit = (ntohl(record.timeToLive) & 0x8000) >> 15;
	m_fieldHandlers[DNSFields::DNS_DO].setAsAvailable(flowRecord);

	return true;
}

bool DNSPlugin::parseDNS(
	std::span<const std::byte> payload,
	const bool isDNSOverTCP,
	FlowRecord& flowRecord,
	DNSContext& dnsContext) noexcept
{
	DNSParser parser;

	auto queryParser
		= [&](const DNSQuestion& query) { return parseQuery(query, flowRecord, dnsContext); };

	auto answerParser
		= [&](const DNSRecord& answer) { return parseAnswer(answer, flowRecord, dnsContext); };

	constexpr auto authorityParser = [](const DNSRecord&) { return true; };

	auto additionalParser
		= [&](const DNSRecord& record) { return parseAdditional(record, flowRecord, dnsContext); };

	const bool parsed = parser.parse(
		payload,
		isDNSOverTCP,
		queryParser,
		answerParser,
		authorityParser,
		additionalParser);
	if (!parsed) {
		return false;
	}

	dnsContext.id = parser.id;
	m_fieldHandlers[DNSFields::DNS_ID].setAsAvailable(flowRecord);

	dnsContext.answerCount = parser.answersCount;
	m_fieldHandlers[DNSFields::DNS_ANSWERS].setAsAvailable(flowRecord);

	dnsContext.responseCode = parser.responseCode;
	m_fieldHandlers[DNSFields::DNS_RCODE].setAsAvailable(flowRecord);

	return true;
}

void DNSPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<DNSContext*>(pluginContext));
}

PluginDataMemoryLayout DNSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(DNSContext),
		.alignment = alignof(DNSContext),
	};
}

static const PluginRegistrar<DNSPlugin, ProcessPluginFactory> dnsRegistrar(dnsPluginManifest);

} // namespace ipxp::process::dns
