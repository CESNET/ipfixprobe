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
	if (flowContext.packet.flowKey.srcPort != 53 && flowContext.packet.flowKey.dstPort != 53) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<DNSData*>(pluginContext));
	// TODO USE VALUES FROM DISSECTOR
	constexpr uint8_t TCP = 6;
	const bool isDNSOverTCP = flowContext.packet.flowKey.l4Protocol == TCP;
	if (parseDNS(flowContext.packet.payload, isDNSOverTCP, flowContext.flowRecord, *pluginData)) {
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
	const bool isDNSOverTCP = flowContext.packet.flowKey.l4Protocol == TCP;
	if (parseDNS(flowContext.packet.payload, isDNSOverTCP, flowContext.flowRecord, *pluginData)) {
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

constexpr
bool DNSPlugin::parseDNS(
	std::span<const std::byte> payload, const bool isDNSOverTCP, FlowRecord& flowRecord, DNSData& pluginData) noexcept
{
	DNSParser parser;

	auto queryParser = [&](const DNSQuestion& query) {
		pluginData.firstQuestionName = query.name.toString();
		m_fieldHandlers[DNSFields::DNS_NAME].setAsAvailable(flowRecord);

		pluginData.firstQuestionType = query.type;
		m_fieldHandlers[DNSFields::DNS_QTYPE].setAsAvailable(flowRecord);

		pluginData.firstQuestionClass = query.recordClass;
		m_fieldHandlers[DNSFields::DNS_CLASS].setAsAvailable(flowRecord);

		return true;
	};

	auto answerParser = [&](const DNSRecord& answer) {
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
	};

	constexpr auto authorityParser = [](const DNSRecord&){
		return true;
	};

	auto additionalParser = [&](const DNSRecord& record) {
		if (record.type != DNSQueryType::OPT) {
			return false;
		}
	
		pluginData.firstOTPPayloadSize = record.recordClass;
		m_fieldHandlers[DNSFields::DNS_PSIZE].setAsAvailable(flowRecord);

		pluginData.dnssecOkBit = (ntohl(record.timeToLive) & 0x8000) >> 15;
		m_fieldHandlers[DNSFields::DNS_DO].setAsAvailable(flowRecord);
	
		return true;
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

std::string DNSPlugin::getName() const noexcept
{
	return dnsPluginManifest.name;
}

PluginDataMemoryLayout DNSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(DNSData),
		.alignment = alignof(DNSData),
	};
}

static const PluginRegistrar<DNSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	dnsRegistrar(dnsPluginManifest);

} // namespace ipxp
