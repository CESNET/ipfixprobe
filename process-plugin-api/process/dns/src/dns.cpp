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


namespace ipxp {


static const PluginManifest packetStatsPluginManifest = {
	.name = "pstats",
	.description = "Pstats process plugin for computing packet bursts stats.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*PSTATSOptParser parser;
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<DNSFields>> fields = {
	{DNSFields::DNS_ID, "DNS_ID"},
	{DNSFields::DNS_ANSWERS, "DNS_ANSWERS"},
	{DNSFields::DNS_RCODE, "DNS_RCODE"},
	{DNSFields::DNS_NAME, "DNS_NAME"},
	{DNSFields::DNS_QTYPE, "DNS_QTYPE"},
	{DNSFields::DNS_CLASS, "DNS_CLASS"},
	{DNSFields::DNS_RR_TTL, "DNS_RR_TTL"},
	{DNSFields::DNS_RLENGTH, "DNS_RLENGTH"},
	{DNSFields::DNS_RDATA, "DNS_RDATA"},
	{DNSFields::DNS_PSIZE, "DNS_PSIZE"},
	{DNSFields::DNS_DO, "DNS_DO"},
};


static FieldSchema createPacketStatsSchema()
{
	FieldSchema schema("dns");

	// TODO

	return schema;
}

DNSPlugin::DNSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createPacketStatsSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction DNSPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	if (packet.flowKey.srcPort != 53 && packet.flowKey.dstPort != 53) {
		return FlowAction::RequestNoData;
	}

	// TODO USE VALUES FROM DISSECTOR
	constexpr uint8_t TCP = 6;
	const bool isDNSOverTCP = packet.l4Protocol == TCP;
	if (parseDNS(packet.payload, isDNSOverTCP)) {
		return FlowAction::Flush;
	}

	return FlowAction::RequestFullData;
}

FlowAction DNSPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	// TODO USE VALUES FROM DISSECTOR
	constexpr uint8_t TCP = 6;
	const bool isDNSOverTCP = packet.l4Protocol == TCP;
	if (parseDNS(packet.payload, isDNSOverTCP)) {
		return FlowAction::Flush;
	}

	return FlowAction::RequestFullData;
}

void DNSPlugin::onFlowExport(FlowRecord& flowRecord) {
	// TODO makeAllAvailable();
}

constexpr
bool DNSPlugin::parseDNS(
	std::span<const std::byte> payload, const bool isDNSOverTCP, FlowRecord& flowRecord) noexcept
{
	DNSParser parser;

	constexpr auto queryParser = [this](const DNSQuestion& query) {
		m_exportData.firstQuestionName = query.name.toString();
		m_fieldHandlers[DNSFields::DNS_NAME].setAsAvailable(flowRecord);

		m_exportData.firstQuestionType = query.type;
		m_fieldHandlers[DNSFields::DNS_QTYPE].setAsAvailable(flowRecord);
		
		m_exportData.firstQuestionClass = query.class;
		m_fieldHandlers[DNSFields::DNS_CLASS].setAsAvailable(flowRecord);

		return true;
	};

	constexpr auto answerParser = [this](const DNSRecord& answer) {
		m_exportData.firstResponseTimeToLive = parser.firstResponse.timeToLive;
		m_fieldHandlers[DNSFields::DNS_RR_TTL].setAsAvailable(flowRecord);
		
		m_exportData.firstResponseAsString 
			= parser.firstResponse.toString(parser.dnsBegin);
		m_fieldHandlers[DNSFields::DNS_RDATA].setAsAvailable(flowRecord);

		m_exportData.firstResponseAsStringLength 
			= m_exportData.firstResponseAsString.size();
		m_fieldHandlers[DNSFields::DNS_RLENGTH].setAsAvailable(flowRecord);

		return true;
	};

	constexpr auto authorityParser = [](const DNSRecord&){
		return true;
	};

	constexpr auto additionalParser = [this](const DNSRecord& record) {
		if (record.type != DNSRecordType::OPT) {
			return false;
		}
	
		m_exportData.firstOTPPayloadSize = record.class;
		m_fieldHandlers[DNSFields::DNS_PSIZE].setAsAvailable(flowRecord);

		m_exportData.dnssecOkBit = record.dnssecOkBit;
		m_fieldHandlers[DNSFields::DNS_DO].setAsAvailable(flowRecord);
	
		return true;
	};

	const bool parsed = parser.parse(
		payload, isDNSOverTCP, queryParser, answerParser,
		authorityParser, additionalParser);
	if (!parsed) {
		return false;
	}

	m_exportData.id = parser.id;
	m_fieldHandlers[DNSFields::DNS_ID].setAsAvailable(flowRecord);

	m_exportData.answersCount = parser.answersCount;
	m_fieldHandlers[DNSFields::DNS_ANSWERS].setAsAvailable(flowRecord);
	
	m_exportData.responseCode = parser.responseCode;
	m_fieldHandlers[DNSFields::DNS_RCODE].setAsAvailable(flowRecord);

	return true;

}

ProcessPlugin* DNSPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<DNSPlugin*>(constructAtAddress), *this);
}

std::string DNSPlugin::getName() const {
	return dnsPluginManifest.name;
}

const void* DNSPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<DNSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	dnsRegistrar(dnsPluginManifest);

} // namespace ipxp
