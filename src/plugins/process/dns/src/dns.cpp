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

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <dnsParser/dnsParser.hpp>
#include <utils/stringViewUtils.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp {

static const PluginManifest dnsPluginManifest = {
	.name = "dns",
	.description = "Dns process plugin for parsing dns traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("dns", "Parse DNS traffic");
			parser.usage(std::cout);*/
		},
};

static FieldSchema createPacketStatsSchema(FieldManager& fieldManager, FieldHandlers<DNSFields>& handlers)
{
	FieldSchema schema = fieldManager.createFieldSchema("dns");

	handlers.insert(DNSFields::DNS_ID, schema.addScalarField("DNS_ID", [](const void* context) {
		return static_cast<const DNSData*>(context)->id;
	}));
	handlers.insert(DNSFields::DNS_ANSWERS, schema.addScalarField("DNS_ANSWERS", [](const void* context) {
		return static_cast<const DNSData*>(context)->answerCount;
	}));
	handlers.insert(DNSFields::DNS_RCODE, schema.addScalarField("DNS_RCODE", [](const void* context) {
		return static_cast<const DNSData*>(context)->responseCode;
	}));
	handlers.insert(DNSFields::DNS_NAME, schema.addScalarField("DNS_NAME", [](const void* context) {
		return toStringView(static_cast<const DNSData*>(context)->firstQuestionName);
	}));
	handlers.insert(DNSFields::DNS_QTYPE, schema.addScalarField("DNS_QTYPE", [](const void* context) {
		return static_cast<const DNSData*>(context)->firstQuestionType;
	}));
	handlers.insert(DNSFields::DNS_CLASS, schema.addScalarField("DNS_CLASS", [](const void* context) {
		return static_cast<const DNSData*>(context)->firstQuestionClass;
	}));
	handlers.insert(DNSFields::DNS_RR_TTL, schema.addScalarField("DNS_RR_TTL", [](const void* context) {
		return static_cast<const DNSData*>(context)->firstResponseTimeToLive;
	}));
	handlers.insert(DNSFields::DNS_RLENGTH, schema.addScalarField("DNS_RLENGTH", [](const void* context) {
		return static_cast<const DNSData*>(context)->firstResponseAsStringLength;
	}));
	handlers.insert(DNSFields::DNS_RDATA, schema.addScalarField("DNS_RDATA", [](const void* context) {
		return toStringView(static_cast<const DNSData*>(context)->firstResponseAsString);
	}));
	handlers.insert(DNSFields::DNS_PSIZE, schema.addScalarField("DNS_PSIZE", [](const void* context) {
		return static_cast<const DNSData*>(context)->firstOTPPayloadSize;
	}));
	handlers.insert(DNSFields::DNS_DO, schema.addScalarField("DNS_DO", [](const void* context) {
		return static_cast<const DNSData*>(context)->dnssecOkBit;
	}));

	return schema;
}

DNSPlugin::DNSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createPacketStatsSchema(manager, m_fieldHandlers);
}

PluginInitResult DNSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t DNS_PORT = 53;
	if (flowContext.packet.src_port != DNS_PORT && flowContext.packet.dst_port != DNS_PORT) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<DNSData*>(pluginContext));
	// TODO USE VALUES FROM DISSECTOR
	constexpr uint8_t TCP = 6;
	const bool isDNSOverTCP = flowContext.packet.ip_proto == TCP;
	if (parseDNS(toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len), isDNSOverTCP, flowContext.flowRecord, *pluginData)) {
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::Flush,
		};
	}

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult DNSPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<DNSData*>(pluginContext);
	
	// TODO USE VALUES FROM DISSECTOR
	constexpr uint8_t TCP = 6;
	const bool isDNSOverTCP = flowContext.packet.ip_proto == TCP;
	if (parseDNS(toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len), isDNSOverTCP, flowContext.flowRecord, *pluginData)) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::Flush,
		};
	}

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

bool DNSPlugin::parseQuery(const DNSQuestion& query, FlowRecord& flowRecord, DNSData& pluginData) noexcept
{
	pluginData.firstQuestionName = query.name.toString();
	m_fieldHandlers[DNSFields::DNS_NAME].setAsAvailable(flowRecord);

	pluginData.firstQuestionType = query.type;
	m_fieldHandlers[DNSFields::DNS_QTYPE].setAsAvailable(flowRecord);

	pluginData.firstQuestionClass = query.recordClass;
	m_fieldHandlers[DNSFields::DNS_CLASS].setAsAvailable(flowRecord);

	return true;
}

bool DNSPlugin::parseAnswer(const DNSRecord& answer, FlowRecord& flowRecord, DNSData& pluginData) noexcept
{
	pluginData.firstResponseTimeToLive = answer.timeToLive;
	m_fieldHandlers[DNSFields::DNS_RR_TTL].setAsAvailable(flowRecord);
	const std::optional<DNSRecordPayloadType> firstResponse 
		= answer.payload.getUnderlyingType(); 
	pluginData.firstResponseAsString = "";
	if (firstResponse.has_value()) {
		pluginData.firstResponseAsString = std::visit(
			[](const auto& record) {
				return record.toDNSString();
			}, *firstResponse);
	}
	m_fieldHandlers[DNSFields::DNS_RDATA].setAsAvailable(flowRecord);

	pluginData.firstResponseAsStringLength 
		= pluginData.firstResponseAsString.size();
	m_fieldHandlers[DNSFields::DNS_RLENGTH].setAsAvailable(flowRecord);

	return true;
}

bool DNSPlugin::parseAdditional(const DNSRecord& record, FlowRecord& flowRecord, DNSData& pluginData) noexcept
{
	if (record.type != DNSQueryType::OPT) {
		return false;
	}

	pluginData.firstOTPPayloadSize = record.recordClass;
	m_fieldHandlers[DNSFields::DNS_PSIZE].setAsAvailable(flowRecord);

	pluginData.dnssecOkBit = (ntohl(record.timeToLive) & 0x8000) >> 15;
	m_fieldHandlers[DNSFields::DNS_DO].setAsAvailable(flowRecord);

	return true;
}

bool DNSPlugin::parseDNS(
	std::span<const std::byte> payload, const bool isDNSOverTCP, FlowRecord& flowRecord, DNSData& pluginData) noexcept
{
	DNSParser parser;

	auto queryParser = [&](const DNSQuestion& query) {
		return parseQuery(query, flowRecord, pluginData);
	};

	auto answerParser = [&](const DNSRecord& answer) {
		return parseAnswer(answer, flowRecord, pluginData);		
	};

	constexpr auto authorityParser = [](const DNSRecord&){
		return true;
	};

	auto additionalParser = [&](const DNSRecord& record) {
		return parseAdditional(record, flowRecord, pluginData);		
	};

	const bool parsed = parser.parse(
		payload, isDNSOverTCP, queryParser, answerParser,
		authorityParser, additionalParser);
	if (!parsed) {
		return false;
	}

	pluginData.id = parser.id;
	m_fieldHandlers[DNSFields::DNS_ID].setAsAvailable(flowRecord);

	pluginData.answerCount = parser.answersCount;
	m_fieldHandlers[DNSFields::DNS_ANSWERS].setAsAvailable(flowRecord);
	
	pluginData.responseCode = parser.responseCode;
	m_fieldHandlers[DNSFields::DNS_RCODE].setAsAvailable(flowRecord);

	return true;
}

void DNSPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<DNSData*>(pluginContext));
}

PluginDataMemoryLayout DNSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(DNSData),
		.alignment = alignof(DNSData),
	};
}

static const PluginRegistrar<DNSPlugin, ProcessPluginFactory> dnsRegistrar(dnsPluginManifest);

} // namespace ipxp
