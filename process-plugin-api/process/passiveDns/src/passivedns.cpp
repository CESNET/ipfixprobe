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

#include "passivedns.hpp"

#include <iostream>
#include <cctype>
#include <arpa/inet.h>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>
#include <dnsParser/dnsParser.hpp>

namespace ipxp {

static const PluginManifest passiveDNSPluginManifest = {
	.name = "passivedns",
	.description = "Passivedns process plugin for parsing DNS A and AAAA records.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("passivedns", "Parse A, AAAA and PTR records from DNS traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<PassiveDNSFields>> fields = {
	{PassiveDNSFields::DNS_ID, "DNS_ID"},
	{PassiveDNSFields::DNS_ATYPE, "DNS_ATYPE"},
	{PassiveDNSFields::DNS_NAME, "DNS_NAME"},
	{PassiveDNSFields::DNS_RR_TTL, "DNS_RR_TTL"},
	{PassiveDNSFields::DNS_IP, "DNS_IP"},
};

static FieldSchema createPassiveDNSSchema()
{
	FieldSchema schema("passivedns");

	// TODO

	return schema;
}

PassiveDNSPlugin::PassiveDNSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createPassiveDNSSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction PassiveDNSPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	constexpr std::size_t DNS_PORT = 53;
	if (packet.flowKey.srcPort == DNS_PORT) {
		parseDNS(packet.payload, flowRecord, packet.flowKey.l4Protocol);
		return FlowAction::Flush;
	}

	return FlowAction::RequestFullData;
}

FlowAction PassiveDNSPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	constexpr std::size_t DNS_PORT = 53;
	if (packet.flowKey.srcPort == DNS_PORT) {
		parseDNS(packet.payload, flowRecord, packet.flowKey.l4Protocol);
		return FlowAction::Flush;
	}

	return FlowAction::RequestFullData;
}

constexpr static
std::optional<IPAddress> getIPFromPTR(std::string ipAsString) noexcept
{
	std::ranges::transform(ipAsString, ipAsString.begin(),
		[](unsigned char c){ return std::tolower(c); });
	if (!ipAsString.empty() && ipAsString.back() == '.') {
		ipAsString.pop_back();
	}

	std::string_view ip4Postfix = ".in-addr.arpa";
	if (ipAsString.ends_with(ip4Postfix)) {
		ipAsString.erase(ipAsString.size() - ip4Postfix.size());
		struct in_addr addr;
		inet_pton(AF_INET, ipAsString.c_str(), &addr);
		return ntohl(addr.s_addr);
	}

	std::string_view ip6Postfix = ".ip6.arpa";
	if (ipAsString.ends_with(ip6Postfix)) {
		ipAsString.erase(ipAsString.size() - ip6Postfix.size());
		// bytes are in reversed order
		std::reverse(ipAsString.begin(), ipAsString.end());
		IPAddress ip;
		//std::array<uint64_t, 2> ip;
		const auto [ptr1, errorCode1] 
			= std::from_chars(
				ipAsString.data(), 
				ipAsString.data() + ipAsString.size()/2, ip.u64[0], 16);
		if (errorCode1 == std::errc()) {
			return std::nullopt;
		}

		const auto [ptr2, errorCode2] 
			= std::from_chars(
				ipAsString.data() + ipAsString.size()/2, 
				ipAsString.data() + ipAsString.size(), ip.u64[1], 16);
		if (errorCode2 == std::errc()) {
			return std::nullopt;
		}

		return ip;
	}

	return std::nullopt;
}

void PassiveDNSPlugin::parseDNS(
	std::span<const std::byte> payload, 
	FlowRecord& flowRecord, 
	const uint8_t l4Protocol) noexcept
{
	constexpr auto queryParser = [](const DNSQuestion&){
		return false;
	};

	auto answerParser = [&](const DNSRecord& record){
		if (record.type == DNSQueryType::A ||
			record.type == DNSQueryType::AAAA ||
			record.type == DNSQueryType::PTR) {

			m_exportData.name.clear();
			std::ranges::copy(record.name.toString() |
				std::views::take(m_exportData.name.capacity()),
				std::back_inserter(m_exportData.name));
			m_fieldHandlers[PassiveDNSFields::DNS_NAME].setAsAvailable(flowRecord);
			
			m_exportData.timeToLive = record.timeToLive;
			m_fieldHandlers[PassiveDNSFields::DNS_RR_TTL].setAsAvailable(flowRecord);

			m_exportData.type = record.type;
			m_fieldHandlers[PassiveDNSFields::DNS_ATYPE].setAsAvailable(flowRecord);
		}

		if (record.type == DNSQueryType::A) {
			const auto& aRecord 
				= std::get<DNSARecord>(*record.payload.getUnderlyingType());
			m_exportData.ip = aRecord.address;
			m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
		}

		if (record.type == DNSQueryType::AAAA) {
			const auto& aaaaRecord 
				= std::get<DNSAAAARecord>(*record.payload.getUnderlyingType());
			m_exportData.ip = aaaaRecord.address;
			m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
		}

		if (record.type == DNSQueryType::PTR) {
			const std::optional<IPAddress> ip = getIPFromPTR(
				record.name.toString());
			if (!ip.has_value()) {
				return false;
			}

			m_exportData.ip = *ip;
			m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
		}

		return false;
	};

	constexpr auto emptyParser = [](const DNSRecord&){
		return false;
	};

	constexpr bool TCP = 6;
	const bool isDNSOverTCP = l4Protocol == TCP;
	DNSParser parser;
	if (!parser.parse(payload, isDNSOverTCP, 
		queryParser, answerParser, emptyParser, emptyParser)) {
		return;
	}

	m_exportData.id = parser.id;
	m_fieldHandlers[PassiveDNSFields::DNS_ID].setAsAvailable(flowRecord);
}

void PassiveDNSPlugin::onFlowExport(FlowRecord&) {}

ProcessPlugin* PassiveDNSPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<PassiveDNSPlugin*>(constructAtAddress), *this);
}

std::string PassiveDNSPlugin::getName() const { 
	return passiveDNSPluginManifest.name; 
}

const void* PassiveDNSPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<PassiveDNSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	passiveDNSRegistrar(passiveDNSPluginManifest);

} // namespace ipxp
