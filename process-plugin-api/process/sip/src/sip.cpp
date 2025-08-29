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

#include "sip.hpp"

#include <iostream>
#include <arpa/inet.h>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <utils/stringUtils.hpp>
#include <utils/stringViewUtils.hpp>
#include <readers/headerFieldReader/headerFieldReader.hpp>

#include "sipMessageType.hpp"


namespace ipxp {

static const PluginManifest sipPluginManifest = {
	.name = "sip",
	.description = "Sip process plugin for parsing sip traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("sip", "Parse SIP traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<SIPFields>> fields = {
	{SIPFields::SIP_MSG_TYPE, "SIP_MSG_TYPE"},
	{SIPFields::SIP_STATUS_CODE, "SIP_STATUS_CODE"},
	{SIPFields::SIP_CSEQ, "SIP_CSEQ"},
	{SIPFields::SIP_CALLING_PARTY, "SIP_CALLING_PARTY"},
	{SIPFields::SIP_CALLED_PARTY, "SIP_CALLED_PARTY"},
	{SIPFields::SIP_CALL_ID, "SIP_CALL_ID"},
	{SIPFields::SIP_USER_AGENT, "SIP_USER_AGENT"},
	{SIPFields::SIP_REQUEST_URI, "SIP_REQUEST_URI"},
	{SIPFields::SIP_VIA, "SIP_VIA"},
};

static FieldSchema createSIPSchema()
{
	FieldSchema schema("sip");

	return schema;
}

SIPPlugin::SIPPlugin(
	[[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createSIPSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

constexpr static
bool fastCheckTypePresence(const uint32_t type) noexcept
{
	constexpr uint32_t typeMask1 = 0x49415449;
	constexpr uint32_t typeMask2 = 0x53494220;

	const uint32_t masked1 = type ^ typeMask1;
	const uint32_t masked2 = type ^ typeMask2;

	constexpr std::size_t magicValue = 0x7efefefe7efefeffL;
	constexpr std::size_t magicValueNegation = 0x8101010181010100L;

	/*
	 * Here we will check if at least one of bytes in the SIP pattern is present in the packet.
	 * Add magic_bits to longword
	 *                | Set those bits which were unchanged by the addition
	 *                |             | Look at the whole bits. If some of them is unchanged,
	 *                |             |            | most likely there is zero byte, ie. our
	 * separator.     v             v            v */
	return (((masked1 + magicValue) ^ ~masked1) & magicValueNegation) ||
			(((masked2 + magicValue) ^ ~masked2) & magicValueNegation);
}

constexpr static
std::optional<SIPMessageType> getMessageType(std::string_view payload) noexcept
{
	constexpr std::size_t MIN_SIP_LENGTH = 64;
	if (payload.size() < MIN_SIP_LENGTH) {
		return std::nullopt;
	}

	/* Get first four bytes of the packet and compare them against the patterns: */
	const uint32_t messageType = ntohl(
		*reinterpret_cast<const uint32_t*>(payload.data()));
	if (!fastCheckTypePresence(messageType)) {
		return std::nullopt;
	}

	constexpr auto sipMethods = std::to_array<std::pair<std::string_view, SIPMessageType>>({
		{"REGISTER", SIPMessageType::REGISTER},
		{"INVITE", SIPMessageType::INVITE},
		{"OPTIONS :sip", SIPMessageType::OPTIONS}, // long form to distinguish from HTTP
		{"CANCEL", SIPMessageType::CANCEL},
		{"INFO", SIPMessageType::INFO},
		{"NOTIFY", SIPMessageType::NOTIFY},
		{"REPLY", SIPMessageType::REPLY},
		{"ACK", SIPMessageType::ACK},
		{"BYE", SIPMessageType::BYE},
		{"SUBSCRIBE", SIPMessageType::SUBSCRIBE},
		{"PUBLISH", SIPMessageType::PUBLISH}
	});
	auto method = std::ranges::find_if(sipMethods, [&](const auto& method) {
		return payload.starts_with(method.first);
	});

	if (method == sipMethods.end()) {
		return std::nullopt;
	}

	/* Notify message is a bit tricky because also Microsoft's SSDP protocol
	* uses HTTP-like structure and NOTIFY message - we must identify false
	* positives here: */
	constexpr std::string_view ssdpNotifyBegin = "NOTIFY * HTTP/1.1";
	if (method->first == "NOTIFY" && payload.starts_with(ssdpNotifyBegin)) {
		return std::nullopt;
	}

	return method->second;
}

constexpr static
std::string_view getURI(std::string_view fieldValue) noexcept
{
	const std::size_t uriBegin = fieldValue.find(':');
	if (uriBegin == std::string_view::npos) {
		return {};
	}

	fieldValue = fieldValue.substr(0, fieldValue.find('>'));
	fieldValue = fieldValue.substr(0, fieldValue.find(';'));

	return fieldValue.substr(uriBegin + 1);
}

constexpr
bool SIPPlugin::parseSIPData(std::string_view payload) noexcept
{
	const std::size_t headerEnd = payload.find('\n');
	if (headerEnd == std::string_view::npos) {
		return false;
	}

	const std::vector<std::string_view> tokens 
		= splitToVector(payload.substr(headerEnd), ' ');

	if (m_exportData.messageType <= 10) {
		/* Note: First SIP request line has syntax: 
		 *	"Method SP Request-URI SP SIP-Version CRLF"
		 * (SP=single space) */
		if (tokens.size() < 2) {
			return false;
		}

		std::ranges::copy(tokens[1] | 
			std::views::take(m_exportData.requestURI.capacity()),
			std::back_inserter(m_exportData.requestURI));
	} 

	if (static_cast<SIPMessageType>(m_exportData.messageType) == SIPMessageType::REPLY) {
		if (tokens.size() < 2) {
			return false;
		}

		if (std::from_chars(
			tokens[1].begin(), 
			tokens[1].end(), 
			m_exportData.statusCode).ec == std::errc()) {
			return false;
		}
	}

	HeaderFieldReader headerFieldReader;
	for (const auto& [key, value] : headerFieldReader.getRange(payload.substr(headerEnd + 1))) {
		if (key == "FROM" || key == "F") {
			m_exportData.callingParty.clear();
			std::ranges::copy(getURI(value) | 
				std::views::take(m_exportData.callingParty.capacity()),
				std::back_inserter(m_exportData.callingParty));
		}

		if (key == "TO" || key == "T") {
			m_exportData.calledParty.clear();
			std::ranges::copy(getURI(value) | 
				std::views::take(m_exportData.calledParty.capacity()),
				std::back_inserter(m_exportData.calledParty));
		}

		if (key == "VIA" || key == "V") {
			pushBackWithDelimiter(getURI(value), m_exportData.via, ';');
		}

		if (key == "CALL-ID" || key == "I") {
			m_exportData.callId.clear();
			std::ranges::copy(value | 
				std::views::take(m_exportData.callId.capacity()),
				std::back_inserter(m_exportData.callId));
		}

		if (key == "USER-AGENT") {
			m_exportData.userAgent.clear();
			std::ranges::copy(value | 
				std::views::take(m_exportData.userAgent.capacity()),
				std::back_inserter(m_exportData.userAgent));
		}

		if (key == "CSeq") {
			m_exportData.commandSequence.clear();
			std::ranges::copy(value | 
				std::views::take(m_exportData.commandSequence.capacity()),
				std::back_inserter(m_exportData.commandSequence));
		}
	}

	return true;
}

FlowAction SIPPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	const std::optional<SIPMessageType> messageType 
		= getMessageType(toStringView(packet.payload));
	if (!messageType.has_value()) {
		return FlowAction::RequestNoData;
	}

	m_exportData.messageType = static_cast<uint16_t>(*messageType);

	if (!parseSIPData(toStringView(packet.payload))) {
		return FlowAction::RequestNoData;
	}

	return FlowAction::RequestTrimmedData;
}

FlowAction SIPPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	if (getMessageType(toStringView(packet.payload)).has_value()) {
		return FlowAction::FlushAndReinsert;
	}

	return FlowAction::RequestNoData;
}

void SIPPlugin::onFlowExport(FlowRecord& flowRecord) {
	// TODO makeAllAvailable(flowRecord) ?
}

ProcessPlugin* SIPPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<SIPPlugin*>(constructAtAddress), *this);
}

std::string SIPPlugin::getName() const {
	return sipPluginManifest.name;
}

const void* SIPPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<SIPPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	sipRegistrar(sipPluginManifest);

} // namespace ipxp
