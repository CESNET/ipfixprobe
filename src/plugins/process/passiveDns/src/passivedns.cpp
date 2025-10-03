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

#include <cctype>
#include <iostream>

#include <arpa/inet.h>
#include <dnsParser/dnsParser.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp {

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

	handlers.insert(
		PassiveDNSFields::DNS_ID,
		schema.addScalarField("DNS_ID", [](const void* context) {
			return static_cast<const PassiveDNSData*>(context)->id;
		}));
	handlers.insert(
		PassiveDNSFields::DNS_ATYPE,
		schema.addScalarField("DNS_ATYPE", [](const void* context) {
			return static_cast<uint16_t>(static_cast<const PassiveDNSData*>(context)->type);
		}));
	handlers.insert(
		PassiveDNSFields::DNS_NAME,
		schema.addScalarField("DNS_NAME", [](const void* context) {
			return toStringView(static_cast<const PassiveDNSData*>(context)->name);
		}));
	handlers.insert(
		PassiveDNSFields::DNS_RR_TTL,
		schema.addScalarField("DNS_RR_TTL", [](const void* context) {
			return static_cast<const PassiveDNSData*>(context)->timeToLive;
		}));
	handlers.insert(
		PassiveDNSFields::DNS_IP,
		schema.addScalarField("DNS_IP", [](const void* context) {
			return static_cast<const PassiveDNSData*>(context)->ip;
		}));

	return schema;
}

PassiveDNSPlugin::PassiveDNSPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createPassiveDNSSchema(manager, m_fieldHandlers);
}

PluginInitResult PassiveDNSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	// TODO DISSCECTOR VALUE
	constexpr std::size_t DNS_PORT = 53;
	if (flowContext.packet.src_port != DNS_PORT && flowContext.packet.dst_port != DNS_PORT) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<PassiveDNSData*>(pluginContext));
	if (flowContext.packet.src_port == DNS_PORT) {
		parseDNS(
			toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len),
			flowContext.flowRecord,
			flowContext.packet.ip_proto,
			*pluginData);
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

PluginUpdateResult PassiveDNSPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<PassiveDNSData*>(pluginContext);
	// TODO DISSCECTOR VALUE
	constexpr std::size_t DNS_PORT = 53;
	if (flowContext.packet.src_port == DNS_PORT) {
		parseDNS(
			toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len),
			flowContext.flowRecord,
			flowContext.packet.ip_proto,
			*pluginData);
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

constexpr static std::optional<IPAddress> getIPFromPTR(std::string ipAsString) noexcept
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
		IPAddress ip;

		if (std::from_chars(
				ipAsString.data(),
				ipAsString.data() + ipAsString.size() / 2,
				ip.u64[0],
				16)
				.ec
			!= std::errc()) {
			return std::nullopt;
		}
		if (std::from_chars(
				ipAsString.data() + ipAsString.size() / 2,
				ipAsString.data() + ipAsString.size(),
				ip.u64[1],
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
	PassiveDNSData& pluginData) noexcept
{
	if (record.type == DNSQueryType::A || record.type == DNSQueryType::AAAA
		|| record.type == DNSQueryType::PTR) {
		pluginData.name.clear();
		std::ranges::copy(
			record.name.toString() | std::views::take(pluginData.name.capacity()),
			std::back_inserter(pluginData.name));
		m_fieldHandlers[PassiveDNSFields::DNS_NAME].setAsAvailable(flowRecord);

		pluginData.timeToLive = record.timeToLive;
		m_fieldHandlers[PassiveDNSFields::DNS_RR_TTL].setAsAvailable(flowRecord);

		pluginData.type = record.type;
		m_fieldHandlers[PassiveDNSFields::DNS_ATYPE].setAsAvailable(flowRecord);
	}

	if (record.type == DNSQueryType::A) {
		const auto aRecord = std::get<DNSARecord>(*record.payload.getUnderlyingType());
		pluginData.ip = aRecord.address;
		m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
	}

	if (record.type == DNSQueryType::AAAA) {
		const auto aaaaRecord = std::get<DNSAAAARecord>(*record.payload.getUnderlyingType());
		pluginData.ip = aaaaRecord.address;
		m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
	}

	if (record.type == DNSQueryType::PTR) {
		const std::optional<IPAddress> ip = getIPFromPTR(record.name.toString());
		if (!ip.has_value()) {
			return false;
		}

		pluginData.ip = *ip;
		m_fieldHandlers[PassiveDNSFields::DNS_IP].setAsAvailable(flowRecord);
	}

	return false;
}

void PassiveDNSPlugin::parseDNS(
	std::span<const std::byte> payload,
	FlowRecord& flowRecord,
	const uint8_t l4Protocol,
	PassiveDNSData& pluginData) noexcept
{
	constexpr auto queryParser = [](const DNSQuestion&) { return false; };

	auto answerParser
		= [&](const DNSRecord& record) { return parseAnswer(record, flowRecord, pluginData); };

	constexpr bool TCP = 6;
	const bool isDNSOverTCP = l4Protocol == TCP;
	DNSParser parser;
	if (!parser.parse(payload, isDNSOverTCP, queryParser, answerParser)) {
		return;
	}

	pluginData.id = parser.id;
	m_fieldHandlers[PassiveDNSFields::DNS_ID].setAsAvailable(flowRecord);
}

void PassiveDNSPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<PassiveDNSData*>(pluginContext));
}

PluginDataMemoryLayout PassiveDNSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(PassiveDNSData),
		.alignment = alignof(PassiveDNSData),
	};
}

static const PluginRegistrar<
	PassiveDNSPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	passiveDNSRegistrar(passiveDNSPluginManifest);

} // namespace ipxp
