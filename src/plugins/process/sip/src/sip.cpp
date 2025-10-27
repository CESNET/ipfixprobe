/**
 * @file
 * @brief Plugin for parsing sip traffic.
 * @author Tomas Jansky <janskto1@fit.cvut.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that calculates packet statistics as flags, acknowledgments, and sequences
 * within flows, stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "sip.hpp"

#include "sipGetters.hpp"
#include "sipMessageType.hpp"

#include <iostream>

#include <arpa/inet.h>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <readers/headerFieldReader/headerFieldReader.hpp>
#include <utils.hpp>
#include <utils/stringUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::sip {

static const PluginManifest sipPluginManifest = {
	.name = "sip",
	.description = "Sip process plugin for parsing sip traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("sip", "Parse SIP traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createSIPSchema(FieldManager& fieldManager, FieldHandlers<SIPFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("sip");

	handlers.insert(
		SIPFields::SIP_MSG_TYPE,
		schema.addScalarField("SIP_MSG_TYPE", getSIPMsgTypeField));

	handlers.insert(
		SIPFields::SIP_STATUS_CODE,
		schema.addScalarField("SIP_STATUS_CODE", getSIPStatusCodeField));

	handlers.insert(SIPFields::SIP_CSEQ, schema.addScalarField("SIP_CSEQ", getSIPCSeqField));

	handlers.insert(
		SIPFields::SIP_CALLING_PARTY,
		schema.addScalarField("SIP_CALLING_PARTY", getSIPCallingPartyField));

	handlers.insert(
		SIPFields::SIP_CALLED_PARTY,
		schema.addScalarField("SIP_CALLED_PARTY", getSIPCalledPartyField));

	handlers.insert(
		SIPFields::SIP_CALL_ID,
		schema.addScalarField("SIP_CALL_ID", getSIPCallIdField));

	handlers.insert(
		SIPFields::SIP_USER_AGENT,
		schema.addScalarField("SIP_USER_AGENT", getSIPUserAgentField));

	handlers.insert(
		SIPFields::SIP_REQUEST_URI,
		schema.addScalarField("SIP_REQUEST_URI", getSIPRequestURIField));

	handlers.insert(SIPFields::SIP_VIA, schema.addScalarField("SIP_VIA", getSIPViaField));

	return schema;
}

SIPPlugin::SIPPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createSIPSchema(manager, m_fieldHandlers);
}

constexpr static bool fastCheckTypePresence(const uint32_t type) noexcept
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
	return (((masked1 + magicValue) ^ ~masked1) & magicValueNegation)
		|| (((masked2 + magicValue) ^ ~masked2) & magicValueNegation);
}

constexpr static std::optional<SIPMessageType> getMessageType(std::string_view payload) noexcept
{
	constexpr std::size_t MIN_SIP_LENGTH = 64;
	if (payload.size() < MIN_SIP_LENGTH) {
		return std::nullopt;
	}

	/* Get first four bytes of the packet and compare them against the patterns: */
	const uint32_t messageType = ntohl(*reinterpret_cast<const uint32_t*>(payload.data()));
	if (!fastCheckTypePresence(messageType)) {
		return std::nullopt;
	}

	constexpr auto sipMethods = std::to_array<std::pair<std::string_view, SIPMessageType>>(
		{{"REGISTER", SIPMessageType::REGISTER},
		 {"INVITE", SIPMessageType::INVITE},
		 {"OPTIONS :sip", SIPMessageType::OPTIONS}, // long form to distinguish from HTTP
		 {"CANCEL", SIPMessageType::CANCEL},
		 {"INFO", SIPMessageType::INFO},
		 {"NOTIFY", SIPMessageType::NOTIFY},
		 {"REPLY", SIPMessageType::REPLY},
		 {"ACK", SIPMessageType::ACK},
		 {"BYE", SIPMessageType::BYE},
		 {"SUBSCRIBE", SIPMessageType::SUBSCRIBE},
		 {"PUBLISH", SIPMessageType::PUBLISH}});
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

constexpr static std::string_view getURI(std::string_view fieldValue) noexcept
{
	const std::size_t uriBegin = fieldValue.find(':');
	if (uriBegin == std::string_view::npos) {
		return {};
	}

	fieldValue = fieldValue.substr(0, fieldValue.find('>'));
	fieldValue = fieldValue.substr(0, fieldValue.find(';'));

	return fieldValue.substr(uriBegin + 1);
}

bool SIPPlugin::parseSIPData(
	std::string_view payload,
	SIPContext& sipContext,
	FlowRecord& flowRecord) noexcept
{
	const std::size_t headerEnd = payload.find('\n');
	if (headerEnd == std::string_view::npos) {
		return false;
	}

	const auto tokens = payload.substr(headerEnd) | std::views::split(' ')
		| std::views::transform([](auto&& rng) {
							return std::string_view(&*rng.begin(), std::ranges::distance(rng));
						})
		| std::ranges::to<std::vector<std::string_view>>();

	if (sipContext.messageType <= 10) {
		/* Note: First SIP request line has syntax:
		 *	"Method SP Request-URI SP SIP-Version CRLF"
		 * (SP=single space) */
		if (tokens.size() < 2) {
			return false;
		}

		std::ranges::copy(
			tokens[1] | std::views::take(sipContext.requestURI.capacity()),
			std::back_inserter(sipContext.requestURI));
		m_fieldHandlers[SIPFields::SIP_REQUEST_URI].setAsAvailable(flowRecord);
	}

	if (static_cast<SIPMessageType>(sipContext.messageType) == SIPMessageType::REPLY) {
		if (tokens.size() < 2) {
			return false;
		}

		if (std::from_chars(tokens[1].begin(), tokens[1].end(), sipContext.statusCode).ec
			== std::errc()) {
			return false;
		}
		m_fieldHandlers[SIPFields::SIP_STATUS_CODE].setAsAvailable(flowRecord);
	}

	HeaderFieldReader headerFieldReader;
	for (const auto& [key, value] : headerFieldReader.getRange(payload.substr(headerEnd + 1))) {
		if (key == "FROM" || key == "F") {
			sipContext.callingParty.clear();
			std::ranges::copy(
				getURI(value) | std::views::take(sipContext.callingParty.capacity()),
				std::back_inserter(sipContext.callingParty));
			m_fieldHandlers[SIPFields::SIP_CALLING_PARTY].setAsAvailable(flowRecord);
		}

		if (key == "TO" || key == "T") {
			sipContext.calledParty.clear();
			std::ranges::copy(
				getURI(value) | std::views::take(sipContext.calledParty.capacity()),
				std::back_inserter(sipContext.calledParty));
			m_fieldHandlers[SIPFields::SIP_CALLED_PARTY].setAsAvailable(flowRecord);
		}

		if (key == "VIA" || key == "V") {
			pushBackWithDelimiter(getURI(value), sipContext.via, ';');
			m_fieldHandlers[SIPFields::SIP_VIA].setAsAvailable(flowRecord);
		}

		if (key == "CALL-ID" || key == "I") {
			sipContext.callId.clear();
			std::ranges::copy(
				value | std::views::take(sipContext.callId.capacity()),
				std::back_inserter(sipContext.callId));
			m_fieldHandlers[SIPFields::SIP_CALL_ID].setAsAvailable(flowRecord);
		}

		if (key == "USER-AGENT") {
			sipContext.userAgent.clear();
			std::ranges::copy(
				value | std::views::take(sipContext.userAgent.capacity()),
				std::back_inserter(sipContext.userAgent));
			m_fieldHandlers[SIPFields::SIP_USER_AGENT].setAsAvailable(flowRecord);
		}

		if (key == "CSeq") {
			sipContext.commandSequence.clear();
			std::ranges::copy(
				value | std::views::take(sipContext.commandSequence.capacity()),
				std::back_inserter(sipContext.commandSequence));
			m_fieldHandlers[SIPFields::SIP_CSEQ].setAsAvailable(flowRecord);
		}
	}

	return true;
}

OnInitResult SIPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	const std::optional<SIPMessageType> messageType
		= getMessageType(toStringView(getPayload(*flowContext.packetContext.packet)));
	if (!messageType.has_value()) {
		return OnInitResult::Irrelevant;
	}

	auto& sipContext = *std::construct_at(reinterpret_cast<SIPContext*>(pluginContext));
	sipContext.messageType = static_cast<uint16_t>(*messageType);
	m_fieldHandlers[SIPFields::SIP_MSG_TYPE].setAsAvailable(flowContext.flowRecord);

	parseSIPData(
		toStringView(getPayload(*flowContext.packetContext.packet)),
		sipContext,
		flowContext.flowRecord);
	return OnInitResult::ConstructedNeedsUpdate;
}

BeforeUpdateResult
SIPPlugin::beforeUpdate(const FlowContext& flowContext, const void* pluginContext) const
{
	if (getMessageType(toStringView(getPayload(*flowContext.packetContext.packet))).has_value()) {
		return BeforeUpdateResult::FlushFlowAndReinsert;
	}

	return BeforeUpdateResult::NoAction;
}

void SIPPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<SIPContext*>(pluginContext));
}

PluginDataMemoryLayout SIPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(SIPContext),
		.alignment = alignof(SIPContext),
	};
}

static const PluginRegistrar<
	SIPPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	sipRegistrar(sipPluginManifest);

} // namespace ipxp::process::sip
