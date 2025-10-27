/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts SMTP fields from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "smtp.hpp"

#include "smtpCommand.hpp"
#include "smtpGetters.hpp"
#include "smtpStatusCode.hpp"

#include <iostream>

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

namespace ipxp::process::smtp {

static const PluginManifest smtpPluginManifest = {
	.name = "smtp",
	.description = "Smtp process plugin for parsing smtp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("smtp", "Parse SMTP traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createSMTPSchema(FieldManager& fieldManager, FieldHandlers<SMTPFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("smtp");

	handlers.insert(
		SMTPFields::SMTP_2XX_STAT_CODE_COUNT,
		schema.addScalarField("SMTP_2XX_STAT_CODE_COUNT", getSMTP2xxStatCodeCountField));
	handlers.insert(
		SMTPFields::SMTP_3XX_STAT_CODE_COUNT,
		schema.addScalarField("SMTP_3XX_STAT_CODE_COUNT", getSMTP3xxStatCodeCountField));
	handlers.insert(
		SMTPFields::SMTP_4XX_STAT_CODE_COUNT,
		schema.addScalarField("SMTP_4XX_STAT_CODE_COUNT", getSMTP4xxStatCodeCountField));
	handlers.insert(
		SMTPFields::SMTP_5XX_STAT_CODE_COUNT,
		schema.addScalarField("SMTP_5XX_STAT_CODE_COUNT", getSMTP5xxStatCodeCountField));
	handlers.insert(
		SMTPFields::SMTP_COMMAND_FLAGS,
		schema.addScalarField("SMTP_COMMAND_FLAGS", getSMTPCommandFlagsField));
	handlers.insert(
		SMTPFields::SMTP_MAIL_CMD_COUNT,
		schema.addScalarField("SMTP_MAIL_CMD_COUNT", getSMTPMailCmdCountField));
	handlers.insert(
		SMTPFields::SMTP_RCPT_CMD_COUNT,
		schema.addScalarField("SMTP_RCPT_CMD_COUNT", getSMTPRcptCmdCountField));
	handlers.insert(
		SMTPFields::SMTP_STAT_CODE_FLAGS,
		schema.addScalarField("SMTP_STAT_CODE_FLAGS", getSMTPStatCodeFlagsField));
	handlers.insert(
		SMTPFields::SMTP_DOMAIN,
		schema.addScalarField("SMTP_DOMAIN", getSMTPDomainField));
	handlers.insert(
		SMTPFields::SMTP_FIRST_RECIPIENT,
		schema.addScalarField("SMTP_FIRST_RECIPIENT", getSMTPFirstRecipientField));
	handlers.insert(
		SMTPFields::SMTP_FIRST_SENDER,
		schema.addScalarField("SMTP_FIRST_SENDER", getSMTPFirstSenderField));

	return schema;
}

SMTPPlugin::SMTPPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createSMTPSchema(manager, m_fieldHandlers);
}

constexpr bool SMTPPlugin::parseResponse(
	std::string_view payload,
	SMTPContext& smtpContext,
	FlowRecord& flowRecord) noexcept
{
	if (payload.size() < 5 || !(payload[3] == ' ' || payload[3] == '-')) {
		return false;
	}

	std::string_view statusPayload = payload.substr(0, 3);

	if (!std::ranges::all_of(statusPayload, [](const unsigned char c) {
			return std::isdigit(c);
		})) {
		return false;
	}

	uint16_t statusCode {0};
	if (std::from_chars(
			statusPayload.data(),
			statusPayload.data() + statusPayload.size(),
			statusCode)
			.ec
		== std::errc()) {
		return false;
	}

	switch (statusCode) {
	case 211:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_211;
		break;
	case 214:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_214;
		break;
	case 220:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_220;
		break;
	case 221:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_221;
		break;
	case 250:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_250;
		break;
	case 251:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_251;
		break;
	case 252:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_252;
		break;
	case 354:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_354;
		break;
	case 421:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_421;
		break;
	case 450:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_450;
		break;
	case 451:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_451;
		break;
	case 452:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_452;
		break;
	case 455:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_455;
		break;
	case 500:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_500;
		break;
	case 501:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_501;
		break;
	case 502:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_502;
		break;
	case 503:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_503;
		break;
	case 504:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_504;
		break;
	case 550:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_550;
		break;
	case 551:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_551;
		break;
	case 552:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_552;
		break;
	case 553:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_553;
		break;
	case 554:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_554;
		break;
	case 555:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_555;
		break;
	default:
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_UNKNOWN;
		break;
	}
	if (std::ranges::equal(
			payload | std::views::transform([](const unsigned char c) { return std::toupper(c); }),
			"SPAM")) {
		smtpContext.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_SPAM;
	}
	m_fieldHandlers[SMTPFields::SMTP_STAT_CODE_FLAGS].setAsAvailable(flowRecord);

	switch (statusPayload[0]) {
	case '2':
		smtpContext.codeCount2xx++;
		m_fieldHandlers[SMTPFields::SMTP_2XX_STAT_CODE_COUNT].setAsAvailable(flowRecord);
		break;
	case '3':
		smtpContext.codeCount3xx++;
		m_fieldHandlers[SMTPFields::SMTP_3XX_STAT_CODE_COUNT].setAsAvailable(flowRecord);
		break;
	case '4':
		smtpContext.codeCount4xx++;
		m_fieldHandlers[SMTPFields::SMTP_4XX_STAT_CODE_COUNT].setAsAvailable(flowRecord);
		break;
	case '5':
		smtpContext.codeCount5xx++;
		m_fieldHandlers[SMTPFields::SMTP_5XX_STAT_CODE_COUNT].setAsAvailable(flowRecord);
		break;
	default:
		return false;
	}
	return true;
}

constexpr static bool isSMTPKeyword(std::string_view keyword) noexcept
{
	return std::ranges::all_of(keyword, [](const unsigned char c) { return std::isupper(c); });
}

constexpr bool SMTPPlugin::parseCommand(
	std::string_view payload,
	SMTPContext& smtpContext,
	FlowRecord& flowRecord) noexcept
{
	if (payload.empty()) {
		return false;
	}

	if (smtpContext.processingState.isDataTransfer) {
		if (payload != ".\r\n") {
			return false;
		}
		smtpContext.processingState.isDataTransfer = false;
		return true;
	}

	const std::size_t headerEnd = payload.find('\r');
	if (headerEnd == std::string_view::npos) {
		return false;
	}
	const std::vector<std::string_view> tokens = splitToVector(payload.substr(0, headerEnd));
	if (tokens.empty()) {
		return false;
	}

	if (tokens[0] == "HELO" || tokens[0] == "EHLO") {
		if (tokens.size() < 2) {
			return false;
		}

		std::ranges::copy(
			tokens[1] | std::views::take(smtpContext.domain.capacity()),
			std::back_inserter(smtpContext.domain));
		m_fieldHandlers[SMTPFields::SMTP_DOMAIN].setAsAvailable(flowRecord);
	}

	if (tokens[0] == "RCPT") {
		smtpContext.mailRecipientCount++;
		m_fieldHandlers[SMTPFields::SMTP_RCPT_CMD_COUNT].setAsAvailable(flowRecord);
		if (tokens.size() < 2) {
			return false;
		}

		const std::size_t semicolonPos = tokens[1].find(':');
		if (semicolonPos == std::string::npos) {
			return false;
		}

		std::ranges::copy(
			tokens[1] | std::views::drop(semicolonPos + 1)
				| std::views::take(smtpContext.firstRecipient.capacity()),
			std::back_inserter(smtpContext.firstRecipient));
		m_fieldHandlers[SMTPFields::SMTP_FIRST_RECIPIENT].setAsAvailable(flowRecord);
	}

	if (tokens[0] == "MAIL") {
		smtpContext.mailCommandCount++;
		m_fieldHandlers[SMTPFields::SMTP_MAIL_CMD_COUNT].setAsAvailable(flowRecord);
		if (tokens.size() < 2) {
			return false;
		}

		const std::size_t semicolonPos = tokens[1].find(':');
		if (semicolonPos == std::string::npos) {
			return false;
		}

		std::ranges::copy(
			tokens[1].substr(semicolonPos + 1)
				| std::views::take(smtpContext.firstSender.capacity()),
			std::back_inserter(smtpContext.firstSender));
		m_fieldHandlers[SMTPFields::SMTP_FIRST_SENDER].setAsAvailable(flowRecord);
	}

	if (tokens[0] == "DATA") {
		smtpContext.processingState.isDataTransfer = true;
	}

	constexpr auto commandsMapping = std::to_array<std::pair<std::string_view, SMTPCommand>>(
		{{"HELO", SMTPCommand::HELO},
		 {"EHLO", SMTPCommand::EHLO},
		 {"MAIL", SMTPCommand::MAIL},
		 {"RCPT", SMTPCommand::RCPT},
		 {"DATA", SMTPCommand::DATA},
		 {"RSET", SMTPCommand::RSET},
		 {"VRFY", SMTPCommand::VRFY},
		 {"EXPN", SMTPCommand::EXPN},
		 {"HELP", SMTPCommand::HELP},
		 {"NOOP", SMTPCommand::NOOP},
		 {"QUIT", SMTPCommand::QUIT}});

	auto commandIt = std::ranges::find_if(commandsMapping, [&](const auto& mapping) {
		return tokens[0] == mapping.first;
	});

	if (commandIt != commandsMapping.end()) {
		smtpContext.commandFlags |= commandIt->second;
	} else if (!isSMTPKeyword(tokens[0])) {
		smtpContext.commandFlags |= SMTPCommand::UNKNOWN;
	}
	m_fieldHandlers[SMTPFields::SMTP_COMMAND_FLAGS].setAsAvailable(flowRecord);

	return true;
}

constexpr OnUpdateResult SMTPPlugin::updateSMTPData(
	std::span<const std::byte> payload,
	const uint16_t srcPort,
	const uint16_t dstPort,
	SMTPContext& smtpContext,
	FlowRecord& flowRecord) noexcept
{
	constexpr uint16_t SMTP_PORT = 25;
	if (dstPort == SMTP_PORT && !parseCommand(toStringView(payload), smtpContext, flowRecord)) {
		return OnUpdateResult::Remove;
	}

	if (srcPort == SMTP_PORT && !parseResponse(toStringView(payload), smtpContext, flowRecord)) {
		return OnUpdateResult::Remove;
	}

	return OnUpdateResult::NeedsUpdate;
}

OnInitResult SMTPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t SMTP_PORT = 25;
	if (flowContext.flowRecord.flowKey.srcPort != SMTP_PORT
		&& flowContext.flowRecord.flowKey.dstPort != SMTP_PORT) {
		return OnInitResult::Irrelevant;
	}
	auto& smtpContext = *std::construct_at(reinterpret_cast<SMTPContext*>(pluginContext));
	const OnUpdateResult updateResult = updateSMTPData(
		getPayload(*flowContext.packetContext.packet),
		flowContext.flowRecord.flowKey.srcPort,
		flowContext.flowRecord.flowKey.dstPort,
		smtpContext,
		flowContext.flowRecord);
	return updateResult == OnUpdateResult::NeedsUpdate ? OnInitResult::ConstructedNeedsUpdate
													   : OnInitResult::ConstructedFinal;
}

OnUpdateResult SMTPPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& pluginData = *reinterpret_cast<SMTPContext*>(pluginContext);
	return updateSMTPData(
		getPayload(*flowContext.packetContext.packet),
		getSrcPort(flowContext.flowRecord, flowContext.packetDirection),
		getDstPort(flowContext.flowRecord, flowContext.packetDirection),
		pluginData,
		flowContext.flowRecord);
}

void SMTPPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<SMTPContext*>(pluginContext));
}

PluginDataMemoryLayout SMTPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(SMTPContext),
		.alignment = alignof(SMTPContext),
	};
}

static const PluginRegistrar<
	SMTPPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	smtpRegistrar(smtpPluginManifest);

} // namespace ipxp::process::smtp
