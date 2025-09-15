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

static FieldSchema createSIPSchema(FieldManager& fieldManager, FieldHandlers<SIPFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("sip");

	handlers.insert(SIPFields::SIP_MSG_TYPE, schema.addScalarField(
		"SIP_MSG_TYPE",
		[](const void* context) { return reinterpret_cast<const SIPData*>(context)->messageType; }
	));
	handlers.insert(SIPFields::SIP_STATUS_CODE, schema.addScalarField(
		"SIP_STATUS_CODE",
		[](const void* context) { return reinterpret_cast<const SIPData*>(context)->statusCode; }
	));
	handlers.insert(SIPFields::SIP_CSEQ, schema.addScalarField(
		"SIP_CSEQ",
		[](const void* context) { return toStringView(reinterpret_cast<const SIPData*>(context)->commandSequence); }
	));
	handlers.insert(SIPFields::SIP_CALLING_PARTY, schema.addScalarField(
		"SIP_CALLING_PARTY",
		[](const void* context) { return toStringView(reinterpret_cast<const SIPData*>(context)->callingParty); }
	));
	handlers.insert(SIPFields::SIP_CALLED_PARTY, schema.addScalarField(
		"SIP_CALLED_PARTY",
		[](const void* context) { return toStringView(reinterpret_cast<const SIPData*>(context)->calledParty); }
	));
	handlers.insert(SIPFields::SIP_CALL_ID, schema.addScalarField(
		"SIP_CALL_ID",
		[](const void* context) { return toStringView(reinterpret_cast<const SIPData*>(context)->callId); }
	));
	handlers.insert(SIPFields::SIP_USER_AGENT, schema.addScalarField(
		"SIP_USER_AGENT",
		[](const void* context) { return toStringView(reinterpret_cast<const SIPData*>(context)->userAgent); }
	));
	handlers.insert(SIPFields::SIP_REQUEST_URI, schema.addScalarField(
		"SIP_REQUEST_URI",
		[](const void* context) { return toStringView(reinterpret_cast<const SIPData*>(context)->requestURI); }
	));
	handlers.insert(SIPFields::SIP_VIA, schema.addScalarField(
		"SIP_VIA",
		[](const void* context) { return toStringView(reinterpret_cast<const SIPData*>(context)->via); }
	));

	return schema;
}

SIPPlugin::SIPPlugin(
	[[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createSIPSchema(manager, m_fieldHandlers);
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
bool SIPPlugin::parseSIPData(std::string_view payload, SIPData& pluginData, FlowRecord& flowRecord) noexcept
{
	const std::size_t headerEnd = payload.find('\n');
	if (headerEnd == std::string_view::npos) {
		return false;
	}

	const std::vector<std::string_view> tokens 
		= splitToVector(payload.substr(headerEnd), ' ');

	if (pluginData.messageType <= 10) {
		/* Note: First SIP request line has syntax: 
		 *	"Method SP Request-URI SP SIP-Version CRLF"
		 * (SP=single space) */
		if (tokens.size() < 2) {
			return false;
		}

		std::ranges::copy(tokens[1] | 
			std::views::take(pluginData.requestURI.capacity()),
			std::back_inserter(pluginData.requestURI));
		m_fieldHandlers[SIPFields::SIP_REQUEST_URI].setAsAvailable(flowRecord);
	} 

	if (static_cast<SIPMessageType>(pluginData.messageType) == SIPMessageType::REPLY) {
		if (tokens.size() < 2) {
			return false;
		}

		if (std::from_chars(
			tokens[1].begin(), 
			tokens[1].end(), 
			pluginData.statusCode).ec == std::errc()) {
			return false;
		}
		m_fieldHandlers[SIPFields::SIP_STATUS_CODE].setAsAvailable(flowRecord);
	}

	HeaderFieldReader headerFieldReader;
	for (const auto& [key, value] : headerFieldReader.getRange(payload.substr(headerEnd + 1))) {
		if (key == "FROM" || key == "F") {
			pluginData.callingParty.clear();
			std::ranges::copy(getURI(value) | 
				std::views::take(pluginData.callingParty.capacity()),
				std::back_inserter(pluginData.callingParty));
			m_fieldHandlers[SIPFields::SIP_CALLING_PARTY].setAsAvailable(flowRecord);
		}

		if (key == "TO" || key == "T") {
			pluginData.calledParty.clear();
			std::ranges::copy(getURI(value) | 
				std::views::take(pluginData.calledParty.capacity()),
				std::back_inserter(pluginData.calledParty));
			m_fieldHandlers[SIPFields::SIP_CALLED_PARTY].setAsAvailable(flowRecord);
		}

		if (key == "VIA" || key == "V") {
			pushBackWithDelimiter(getURI(value), pluginData.via, ';');
			m_fieldHandlers[SIPFields::SIP_VIA].setAsAvailable(flowRecord);
		}

		if (key == "CALL-ID" || key == "I") {
			pluginData.callId.clear();
			std::ranges::copy(value | 
				std::views::take(pluginData.callId.capacity()),
				std::back_inserter(pluginData.callId));
			m_fieldHandlers[SIPFields::SIP_CALL_ID].setAsAvailable(flowRecord);
		}

		if (key == "USER-AGENT") {
			pluginData.userAgent.clear();
			std::ranges::copy(value | 
				std::views::take(pluginData.userAgent.capacity()),
				std::back_inserter(pluginData.userAgent));
			m_fieldHandlers[SIPFields::SIP_USER_AGENT].setAsAvailable(flowRecord);
		}

		if (key == "CSeq") {
			pluginData.commandSequence.clear();
			std::ranges::copy(value | 
				std::views::take(pluginData.commandSequence.capacity()),
				std::back_inserter(pluginData.commandSequence));
			m_fieldHandlers[SIPFields::SIP_CSEQ].setAsAvailable(flowRecord);
		}
	}

	return true;
}

PluginInitResult SIPPlugin::onInit(const FlowContext& flowContext, void* pluginContext) 
{
	const std::optional<SIPMessageType> messageType 
		= getMessageType(toStringView(flowContext.packet.payload, flowContext.packet.payload_len));
	if (!messageType.has_value()) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<SIPData*>(pluginContext));
	pluginData->messageType = static_cast<uint16_t>(*messageType);
	m_fieldHandlers[SIPFields::SIP_MSG_TYPE].setAsAvailable(flowContext.flowRecord);

	if (!parseSIPData(toStringView(flowContext.packet.payload, flowContext.packet.payload_len), *pluginData, flowContext.flowRecord)) {
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}


PluginUpdateResult SIPPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	if (getMessageType(toStringView(flowContext.packet.payload, flowContext.packet.payload_len)).has_value()) {
		// TODO Flush and reinsert
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction
		};
	}

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction
	};
}

void SIPPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<SIPData*>(pluginContext));
}

PluginDataMemoryLayout SIPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(SIPData),
		.alignment = alignof(SIPData),
	};
}

static const PluginRegistrar<SIPPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	sipRegistrar(sipPluginManifest);

} // namespace ipxp
