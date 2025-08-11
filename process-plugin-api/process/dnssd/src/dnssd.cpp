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

const inline std::vector<FieldPair<DNSDFields>> fields = {
	{DNSDFields::DNSSD_QUERIES, "DNSSD_QUERIES"},
	{DNSDFields::DNSSD_RESPONSES, "DNSSD_RESPONSES"},
};

static FieldSchema createDNSSDSchema()
{
	FieldSchema schema("dnssd");

	// TODO

	return schema;
}

DNSSDPlugin::DNSSDPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createDNSSDSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction DNSSDPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	constexpr uint16_t DNSSD_PORT = 5353;
	if (packet.flowKey.srcPort != DNSSD_PORT && 
		packet.flowKey.dstPort != DNSSD_PORT) {
		return FlowAction::RequestNoData;
	}

	// TODO USE VALUES FROM DISSECTOR
	constexpr std::size_t TCP = 6;
	const bool isDNSoverTCP = (packet.flowKey.protocol == TCP);
	if (!parseDNSSD(packet.payload(), isDNSoverTCP, flowRecord)) {
		return FlowAction::RequestNoData;
	}

	return FlowAction::RequestFullData;
}

FlowAction DNSSDPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	// TODO USE VALUES FROM DISSECTOR
	constexpr std::size_t TCP = 6;
	const bool isDNSoverTCP = (packet.flowKey.protocol == TCP);
	if (!parseDNSSD(packet.payload(), isDNSoverTCP, flowRecord)) {
		return FlowAction::RequestNoData;
	}

	return FlowAction::RequestFullData;
}

constexpr
void DNSSDPlugin::parseDNSSD(
	std::span<const std::byte> payload, 
	const bool isDNSoverTCP,
	FlowRecord& flowRecord) noexcept
{
	DNSParser parser;

	constexpr auto queryParser = [this](const DNSQuestion& query) {
		m_exportData.findOrInsert(query.name);
		return false;
	};

	constexpr auto answerParser = [this](const DNSRecord& answer) {

		if (answer.type == DNSRecordType::SRV) {
			DNSSDRecord& record = m_exportData.findOrInsert(answer.name);
			const auto& srv 
				= std::get<const DNSSRVRecord&>(answer.payload.getUnderlyingType());
			record.srvPort = srv.port;
			record.srvTarget = srv.target;
		}

		if (answer.type == DNSRecordType::TXT) {
			DNSSDRecord& record = m_exportData.findOrInsert(answer.name);
			const auto& txt
				= std::get<const DNSTXTRecord&>(answer.payload.getUnderlyingType());
			record.txtContent.push_back(txt.content);
		}

		if (answer.type == DNSRecordType::HINFO) {
			DNSSDRecord& record = m_exportData.findOrInsert(answer.name);
			const auto& hinfo
				= std::get<const DNSHINFORecord&>(answer.payload.getUnderlyingType());
			record.hardwareInfo = hinfo.content;
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

void DNSSDPlugin::onFlowExport(FlowRecord& flowRecord) 
{
	if (m_exportData.requests.empty()) {
		return;
	}

	std::ranges::for_each(m_exportData.requests, 
		[](const DNSSDRecord& response) {
			const std::string& name = response.name.toString();
			if (name.size() < 
				m_exportData.queries.capacity() - m_exportData.queries.size()) {
				m_exportData.queries.push_back(name);
				m_exportData.queries.push_back(';');
			}
		});

	std::ranges::for_each(m_exportData.requests, 
		[](const DNSSDRecord& response) {
			const std::string& value = response.toString() + ';';
			std::ranges::copy(value | 
				std::views::take(
					m_exportData.responses.capacity() - 
					m_exportData.responses.size()),
				std::back_inserter(m_exportData.responses));
		});
	
	// TODO makeAllAvailable()
}

ProcessPlugin* DNSSDPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<DNSSDPlugin*>(constructAtAddress), *this);
}

std::string DNSSDPlugin::getName() const { 
	return dnssdPluginManifest.name; 
}

const void* DNSSDPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<DNSSDPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	dnssdRegistrar(dnssdPluginManifest);

} // namespace ipxp
