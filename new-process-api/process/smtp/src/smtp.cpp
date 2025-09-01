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

#include "smtp.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

#include <utils/stringViewUtils.hpp>

#include "smtpStatusCode.hpp"
#include "smtpCommand.hpp"

namespace ipxp {

static const PluginManifest smtpPluginManifest = {
	.name = "smtp",
	.description = "Smtp process plugin for parsing smtp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("smtp", "Parse SMTP traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<SMTPFields>> fields = {
	{SMTPFields::SMTP_2XX_STAT_CODE_COUNT, "SMTP_2XX_STAT_CODE_COUNT"},
	{SMTPFields::SMTP_3XX_STAT_CODE_COUNT, "SMTP_3XX_STAT_CODE_COUNT"},
	{SMTPFields::SMTP_4XX_STAT_CODE_COUNT, "SMTP_4XX_STAT_CODE_COUNT"},
	{SMTPFields::SMTP_5XX_STAT_CODE_COUNT, "SMTP_5XX_STAT_CODE_COUNT"},
	{SMTPFields::SMTP_COMMAND_FLAGS, "SMTP_COMMAND_FLAGS"},
	{SMTPFields::SMTP_MAIL_CMD_COUNT, "SMTP_MAIL_CMD_COUNT"},
	{SMTPFields::SMTP_RCPT_CMD_COUNT, "SMTP_RCPT_CMD_COUNT"},
	{SMTPFields::SMTP_STAT_CODE_FLAGS, "SMTP_STAT_CODE_FLAGS"},
	{SMTPFields::SMTP_DOMAIN, "SMTP_DOMAIN"},
	{SMTPFields::SMTP_FIRST_RECIPIENT, "SMTP_FIRST_RECIPIENT"},
	{SMTPFields::SMTP_FIRST_SENDER, "SMTP_FIRST_SENDER"},
};


static FieldSchema createSMTPSchema()
{
	FieldSchema schema("smtp");
	//TODO
	return schema;
}

SMTPPlugin::SMTPPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createSMTPSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

constexpr
bool SMTPPlugin::parseResponse(std::string_view payload) noexcept
{
	if (payload.size() < 5 || !(payload[3] == ' ' || payload[3] == '-')) {
		return false;
	}

	std::string_view statusPayload = payload.substr(0, 3);

	if (!std::ranges::all_of(statusPayload, 
		[](const unsigned char c){
			 return std::isdigit(c); 
			})) {
		return false;
	}

	uint16_t statusCode{0};
	if (std::from_chars(
		statusPayload.data(), 
		statusPayload.data() + statusPayload.size(), 
		statusCode).ec == std::errc()) {
		return false;
	}

	switch (statusCode) {
	case 211:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_211;
		break;
	case 214:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_214;
		break;
	case 220:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_220;
		break;
	case 221:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_221;
		break;
	case 250:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_250;
		break;
	case 251:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_251;
		break;
	case 252:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_252;
		break;
	case 354:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_354;
		break;
	case 421:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_421;
		break;
	case 450:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_450;
		break;
	case 451:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_451;
		break;
	case 452:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_452;
		break;
	case 455:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_455;
		break;
	case 500:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_500;
		break;
	case 501:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_501;
		break;
	case 502:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_502;
		break;
	case 503:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_503;
		break;
	case 504:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_504;
		break;
	case 550:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_550;
		break;
	case 551:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_551;
		break;
	case 552:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_552;
		break;
	case 553:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_553;
		break;
	case 554:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_554;
		break;
	case 555:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_555;
		break;
	default:
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_UNKNOWN;
		break;
	}

	if (std::ranges::equal(payload | 
		std::views::transform([](const unsigned char c){
			 return std::toupper(c); 
			}), "SPAM")) {
		m_exportData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_SPAM;
	}

	switch (statusPayload[0]) {
	case '2':
		m_exportData.codeCount2xx++;
		break;
	case '3':
		m_exportData.codeCount3xx++;
		break;
	case '4':
		m_exportData.codeCount4xx++;
		break;
	case '5':
		m_exportData.codeCount5xx++;
		break;
	default:
		return false;
	}

	return true;
}

constexpr static
bool isSMTPKeyword(std::string_view keyword) noexcept
{
	return std::ranges::all_of(keyword, 
		[](const unsigned char c){
			return std::isupper(c); 
		});
}

constexpr
bool SMTPPlugin::parseCommand(std::string_view payload) noexcept
{
	if (payload.empty()) {
		return false;
	}

	if (m_isDataTransfer) {
		if (payload != ".\r\n") {
			return false;
		}
		m_isDataTransfer = false;
		return true;
	}

	const std::size_t headerEnd = payload.find('\r');
	if (headerEnd == std::string_view::npos) {
		return false;
	}
	const std::vector<std::string_view> tokens 
		= splitToVector(payload.substr(0, headerEnd));
	if (tokens.empty()) {
		return false;
	}

	if (tokens[0] == "HELO" || tokens[0] == "EHLO") {
		if (tokens.size() < 2) {
			return false;
		}

		std::ranges::copy(tokens[1] | 
			std::views::take(m_exportData.domain.capacity()),
			std::back_inserter(m_exportData.domain));
	}

	if (tokens[0] == "RCPT") {
		m_exportData.mailRecipientCount++;

		if (tokens.size() < 2) {
			return false;
		}

		const std::size_t semicolonPos = tokens[1].find(':');
		if (semicolonPos == std::string::npos) {
			return false;
		}

		std::ranges::copy(tokens[1] | 
			std::views::drop(semicolonPos + 1) |
			std::views::take(m_exportData.firstRecipient.capacity()),
			std::back_inserter(m_exportData.firstRecipient));
	}

	if (tokens[0] == "MAIL") {
		m_exportData.mailCommandCount++;
		
		if (tokens.size() < 2) {
			return false;
		}
		
		const std::size_t semicolonPos = tokens[1].find(':');
		if (semicolonPos == std::string::npos) {
			return false;
		}
		
		std::ranges::copy(tokens[1].substr(semicolonPos + 1) | 
			std::views::take(m_exportData.firstSender.capacity()),
			std::back_inserter(m_exportData.firstSender));
	}

	if (tokens[0] == "DATA") {
		m_isDataTransfer = true;
	}

	constexpr auto commandsMapping 
		= std::to_array<std::pair<std::string_view, SMTPCommand>>({
			{"HELO", SMTPCommand::HELO},
			{"EHLO", SMTPCommand::EHLO},
			{"MAIL", SMTPCommand::MAIL},
			{"RCPT", SMTPCommand::RCPT},
			{"DATA", SMTPCommand::DATA},
			{"RSET", SMTPCommand::RSET},
			{"VRFY", SMTPCommand::VRFY},
			{"EXPN", SMTPCommand::EXPN},
			{"HELP", SMTPCommand::HELP},
			{"NOOP", SMTPCommand::NOOP},
			{"QUIT", SMTPCommand::QUIT}
		});

	auto commandIt = std::ranges::find_if(commandsMapping,
		[&](const auto& mapping) {
			return tokens[0] == mapping.first;
		});

	if (commandIt != commandsMapping.end()) {
		m_exportData.commandFlags |= commandIt->second;
	} else if (!isSMTPKeyword(tokens[0])) {
		m_exportData.commandFlags |= SMTPCommand::UNKNOWN;
	}

	return true;
}

constexpr
FlowAction SMTPPlugin::updateSMTPData(
	std::span<const std::byte> payload, const uint16_t srcPort, const uint16_t dstPort) noexcept
{
	constexpr uint16_t SMTP_PORT = 25;
	if (dstPort == SMTP_PORT && !parseCommand(toStringView(payload))) {
		return FlowAction::RequestNoData;
	}

	if (srcPort == SMTP_PORT && !parseResponse(toStringView(payload))) {
		return FlowAction::RequestNoData;
	}

	return FlowAction::RequestNoData;
}

FlowAction SMTPPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	return updateSMTPData(
		packet.payload, packet.flowKey.srcPort, packet.flowKey.dstPort);
}

FlowAction SMTPPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	return updateSMTPData(
		packet.payload, packet.flowKey.srcPort, packet.flowKey.dstPort);
}

void SMTPPlugin::onFlowExport(FlowRecord& flowRecord) {
	// TODO make all available
}

ProcessPlugin* SMTPPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<SMTPPlugin*>(constructAtAddress), *this);
}

std::string SMTPPlugin::getName() const {
	return smtpPluginManifest.name;
}

const void* SMTPPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<SMTPPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	smtpRegistrar(smtpPluginManifest);

} // namespace ipxp
