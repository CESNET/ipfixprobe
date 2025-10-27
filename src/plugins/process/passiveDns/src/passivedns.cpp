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

#include "passivednsGetters.hpp"

#include <cctype>
#include <iostream>

#include <arpa/inet.h>
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

namespace ipxp::process::passivedns {

static const PluginManifest passiveDNSPluginManifest = {
	.name = "passivedns",
	.description = "Passivedns process plugin for parsing DNS A and AAAA records.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("passivedns", "Parse A, AAAA and PTR records from DNS traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup createPassiveDNSSchema(
	FieldManager& fieldManager,
	FieldHandlers<PassiveDNSFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("passivedns");

	handlers.insert(PassiveDNSFields::DNS_ID, schema.addScalarField("DNS_ID", getDNSIDField));
	handlers.insert(
		PassiveDNSFields::DNS_ATYPE,
		schema.addScalarField("DNS_ATYPE", getDNSATYPEField));
	handlers.insert(PassiveDNSFields::DNS_NAME, schema.addScalarField("DNS_NAME", getDNSNameField));
	handlers.insert(
		PassiveDNSFields::DNS_RR_TTL,
		schema.addScalarField("DNS_RR_TTL", getDNSRRTTLField));
	handlers.insert(PassiveDNSFields::DNS_IP, schema.addScalarField("DNS_IP", getDNSIPField));

	return schema;
}

PassiveDNSPlugin::PassiveDNSPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createPassiveDNSSchema(manager, m_fieldHandlers);
}

OnInitResult PassiveDNSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr std::size_t DNS_PORT = 53;
	if (flowContext.flowRecord.flowKey.srcPort != DNS_PORT
		&& flowContext.flowRecord.flowKey.dstPort != DNS_PORT) {
		return OnInitResult::Irrelevant;
	}

	auto& passiveDNSContext
		= *std::construct_at(reinterpret_cast<PassiveDNSContext*>(pluginContext));
	if (flowContext.flowRecord.flowKey.srcPort == DNS_PORT) {
		parseDNS(
			getPayload(*flowContext.packetContext.packet),
			flowContext.flowRecord,
			flowContext.flowRecord.flowKey.l4Protocol,
			passiveDNSContext);
		return OnInitResult::ConstructedFinal;
	}

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult PassiveDNSPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& passiveDNSContext = *reinterpret_cast<PassiveDNSContext*>(pluginContext);
	constexpr std::size_t DNS_PORT = 53;
	if (getDstPort(flowContext.flowRecord, flowContext.packetDirection) == DNS_PORT) {
		parseDNS(
			getPayload(*flowContext.packetContext.packet),
			flowContext.flowRecord,
			flowContext.flowRecord.flowKey.l4Protocol,
			passiveDNSContext);
		return OnUpdateResult::FlushFlow;
	}

	return OnUpdateResult::NeedsUpdate;
}

constexpr static std::optional<IPAddressVariant> getIPFromPTR(std::string ipAsString) noexcept
{
	std::ranges::transform(ipAsString, ipAsString.begin(), [](unsigned char c) {
		return std::tolower(c);
	});
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
		IPAddressVariant ip;

		if (std::from_chars(
				ipAsString.data(),
				ipAsString.data() + ipAsString.size() / 2,
				*reinterpret_cast<uint64_t*>(ip.value.data()),
				16)
				.ec
			!= std::errc()) {
			return std::nullopt;
		}
		if (std::from_chars(
				ipAsString.data() + ipAsString.size() / 2,
				ipAsString.data() + ipAsString.size(),
				*reinterpret_cast<uint64_t*>(ip.value.data() + sizeof(uint64_t)),
				16)
				.ec
			!= std::errc()) {
			return std::nullopt;
		}

		return ip;
	}

	return std::nullopt;
}

bool PassiveDNSPlugin::parseAnswer(
	const DNSRecord& record,
	FlowRecord& flowRecord,
	PassiveDNSContext& pluginContext) noexcept
{
	if (record.type == DNSQueryType::A || record.type == DNSQueryType::AAAA
		|| record.type == DNSQueryType::PTR) {
		pluginContext.name.clear();
		std::ranges::copy(
			record.name.toString() | std::views::take(pluginContext.name.capacity()),
			std::back_inserter(pluginContext.name));
		m_fieldHandlers[PassiveDNSFields::DNS_NAME].setAsAvailable(flowRecord);

		pluginContext.timeToLive = record.timeToLive;
		m_fieldHandlers[PassiveDNSFields::DNS_RR_TTL].setAsAvailable(flowRecord);

		pluginContext.type = record.type;
		m_fieldHandlers[PassiveDNSFields::DNS_ATYPE].setAsAvailable(flowRecord);
	}

	if (record.type == DNSQueryType::A) {
		const auto aRecord = std::get<DNSARecord>(*record.payload.getUnderlyingType());
		pluginContext.ip = aRecord.address;
		m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
	}

	if (record.type == DNSQueryType::AAAA) {
		const auto aaaaRecord = std::get<DNSAAAARecord>(*record.payload.getUnderlyingType());
		pluginContext.ip = aaaaRecord.address;
		m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
	}

	if (record.type == DNSQueryType::PTR) {
		const std::optional<IPAddressVariant> ip = getIPFromPTR(record.name.toString());
		if (!ip.has_value()) {
			return false;
		}

		pluginContext.ip = *ip;
		m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
	}

	return false;
}

void PassiveDNSPlugin::parseDNS(
	std::span<const std::byte> payload,
	FlowRecord& flowRecord,
	const uint8_t l4Protocol,
	PassiveDNSContext& pluginContext) noexcept
{
	constexpr auto queryParser = [](const DNSQuestion&) { return false; };

	auto answerParser
		= [&](const DNSRecord& record) { return parseAnswer(record, flowRecord, pluginContext); };

	constexpr bool TCP = 6;
	const bool isDNSOverTCP = l4Protocol == TCP;
	DNSParser parser;
	if (!parser.parse(payload, isDNSOverTCP, queryParser, answerParser)) {
		return;
	}

	pluginContext.id = parser.id;
	m_fieldHandlers[PassiveDNSFields::DNS_ID].setAsAvailable(flowRecord);
}

void PassiveDNSPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<PassiveDNSContext*>(pluginContext));
}

PluginDataMemoryLayout PassiveDNSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(PassiveDNSContext),
		.alignment = alignof(PassiveDNSContext),
	};
}

static const PluginRegistrar<
	PassiveDNSPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	passiveDNSRegistrar(passiveDNSPluginManifest);

} // namespace ipxp::process::passivedns
