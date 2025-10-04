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
#include "smtpStatusCode.hpp"

#include <iostream>

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
		schema.addScalarField("SMTP_2XX_STAT_CODE_COUNT", [](const void* context) {
			return reinterpret_cast<const SMTPData*>(context)->codeCount2xx;
		}));
	handlers.insert(
		SMTPFields::SMTP_3XX_STAT_CODE_COUNT,
		schema.addScalarField("SMTP_3XX_STAT_CODE_COUNT", [](const void* context) {
			return reinterpret_cast<const SMTPData*>(context)->codeCount3xx;
		}));
	handlers.insert(
		SMTPFields::SMTP_4XX_STAT_CODE_COUNT,
		schema.addScalarField("SMTP_4XX_STAT_CODE_COUNT", [](const void* context) {
			return reinterpret_cast<const SMTPData*>(context)->codeCount4xx;
		}));
	handlers.insert(
		SMTPFields::SMTP_5XX_STAT_CODE_COUNT,
		schema.addScalarField("SMTP_5XX_STAT_CODE_COUNT", [](const void* context) {
			return reinterpret_cast<const SMTPData*>(context)->codeCount5xx;
		}));
	handlers.insert(
		SMTPFields::SMTP_COMMAND_FLAGS,
		schema.addScalarField("SMTP_COMMAND_FLAGS", [](const void* context) {
			return reinterpret_cast<const SMTPData*>(context)->commandFlags;
		}));
	handlers.insert(
		SMTPFields::SMTP_MAIL_CMD_COUNT,
		schema.addScalarField("SMTP_MAIL_CMD_COUNT", [](const void* context) {
			return reinterpret_cast<const SMTPData*>(context)->mailCommandCount;
		}));
	handlers.insert(
		SMTPFields::SMTP_RCPT_CMD_COUNT,
		schema.addScalarField("SMTP_RCPT_CMD_COUNT", [](const void* context) {
			return reinterpret_cast<const SMTPData*>(context)->mailRecipientCount;
		}));
	handlers.insert(
		SMTPFields::SMTP_STAT_CODE_FLAGS,
		schema.addScalarField("SMTP_STAT_CODE_FLAGS", [](const void* context) {
			return reinterpret_cast<const SMTPData*>(context)->mailCodeFlags;
		}));
	handlers.insert(
		SMTPFields::SMTP_DOMAIN,
		schema.addScalarField("SMTP_DOMAIN", [](const void* context) {
			return toStringView(reinterpret_cast<const SMTPData*>(context)->domain);
		}));
	handlers.insert(
		SMTPFields::SMTP_FIRST_RECIPIENT,
		schema.addScalarField("SMTP_FIRST_RECIPIENT", [](const void* context) {
			return toStringView(reinterpret_cast<const SMTPData*>(context)->firstRecipient);
		}));
	handlers.insert(
		SMTPFields::SMTP_FIRST_SENDER,
		schema.addScalarField("SMTP_FIRST_SENDER", [](const void* context) {
			return toStringView(reinterpret_cast<const SMTPData*>(context)->firstSender);
		}));

	return schema;
}

SMTPPlugin::SMTPPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createSMTPSchema(manager, m_fieldHandlers);
}

constexpr bool SMTPPlugin::parseResponse(
	std::string_view payload,
	SMTPData& pluginData,
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
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_211;
		break;
	case 214:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_214;
		break;
	case 220:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_220;
		break;
	case 221:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_221;
		break;
	case 250:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_250;
		break;
	case 251:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_251;
		break;
	case 252:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_252;
		break;
	case 354:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_354;
		break;
	case 421:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_421;
		break;
	case 450:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_450;
		break;
	case 451:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_451;
		break;
	case 452:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_452;
		break;
	case 455:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_455;
		break;
	case 500:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_500;
		break;
	case 501:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_501;
		break;
	case 502:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_502;
		break;
	case 503:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_503;
		break;
	case 504:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_504;
		break;
	case 550:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_550;
		break;
	case 551:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_551;
		break;
	case 552:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_552;
		break;
	case 553:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_553;
		break;
	case 554:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_554;
		break;
	case 555:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_555;
		break;
	default:
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_UNKNOWN;
		break;
	}
	if (std::ranges::equal(
			payload | std::views::transform([](const unsigned char c) { return std::toupper(c); }),
			"SPAM")) {
		pluginData.mailCodeFlags |= SMTPStatusCode::STATUS_CODE_SPAM;
	}
	m_fieldHandlers[SMTPFields::SMTP_STAT_CODE_FLAGS].setAsAvailable(flowRecord);

	switch (statusPayload[0]) {
	case '2':
		pluginData.codeCount2xx++;
		m_fieldHandlers[SMTPFields::SMTP_2XX_STAT_CODE_COUNT].setAsAvailable(flowRecord);
		break;
	case '3':
		pluginData.codeCount3xx++;
		m_fieldHandlers[SMTPFields::SMTP_3XX_STAT_CODE_COUNT].setAsAvailable(flowRecord);
		break;
	case '4':
		pluginData.codeCount4xx++;
		m_fieldHandlers[SMTPFields::SMTP_4XX_STAT_CODE_COUNT].setAsAvailable(flowRecord);
		break;
	case '5':
		pluginData.codeCount5xx++;
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
	SMTPData& pluginData,
	FlowRecord& flowRecord) noexcept
{
	if (payload.empty()) {
		return false;
	}

	if (pluginData.processingState.isDataTransfer) {
		if (payload != ".\r\n") {
			return false;
		}
		pluginData.processingState.isDataTransfer = false;
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
			tokens[1] | std::views::take(pluginData.domain.capacity()),
			std::back_inserter(pluginData.domain));
		m_fieldHandlers[SMTPFields::SMTP_DOMAIN].setAsAvailable(flowRecord);
	}

	if (tokens[0] == "RCPT") {
		pluginData.mailRecipientCount++;
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
				| std::views::take(pluginData.firstRecipient.capacity()),
			std::back_inserter(pluginData.firstRecipient));
		m_fieldHandlers[SMTPFields::SMTP_FIRST_RECIPIENT].setAsAvailable(flowRecord);
	}

	if (tokens[0] == "MAIL") {
		pluginData.mailCommandCount++;
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
				| std::views::take(pluginData.firstSender.capacity()),
			std::back_inserter(pluginData.firstSender));
		m_fieldHandlers[SMTPFields::SMTP_FIRST_SENDER].setAsAvailable(flowRecord);
	}

	if (tokens[0] == "DATA") {
		pluginData.processingState.isDataTransfer = true;
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
		pluginData.commandFlags |= commandIt->second;
	} else if (!isSMTPKeyword(tokens[0])) {
		pluginData.commandFlags |= SMTPCommand::UNKNOWN;
	}
	m_fieldHandlers[SMTPFields::SMTP_COMMAND_FLAGS].setAsAvailable(flowRecord);

	return true;
}

constexpr PluginUpdateResult SMTPPlugin::updateSMTPData(
	std::span<const std::byte> payload,
	const uint16_t srcPort,
	const uint16_t dstPort,
	SMTPData& pluginData,
	FlowRecord& flowRecord) noexcept
{
	constexpr uint16_t SMTP_PORT = 25;
	if (dstPort == SMTP_PORT && !parseCommand(toStringView(payload), pluginData, flowRecord)) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	if (srcPort == SMTP_PORT && !parseResponse(toStringView(payload), pluginData, flowRecord)) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	return {
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::NoAction,
	};
}

PluginInitResult SMTPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t SMTP_PORT = 25;
	if (flowContext.packet.src_port != SMTP_PORT && flowContext.packet.dst_port != SMTP_PORT) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}
	auto* pluginData = std::construct_at(reinterpret_cast<SMTPData*>(pluginContext));
	auto [updateRequirement, flowAction] = updateSMTPData(
		toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len),
		flowContext.packet.src_port,
		flowContext.packet.dst_port,
		*pluginData,
		flowContext.flowRecord);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = updateRequirement,
		.flowAction = flowAction,
	};
}

PluginUpdateResult SMTPPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<SMTPData*>(pluginContext);
	return updateSMTPData(
		toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len),
		flowContext.packet.src_port,
		flowContext.packet.dst_port,
		*pluginData,
		flowContext.flowRecord);
}

void SMTPPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<SMTPData*>(pluginContext));
}

PluginDataMemoryLayout SMTPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(SMTPData),
		.alignment = alignof(SMTPData),
	};
}

static const PluginRegistrar<
	SMTPPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	smtpRegistrar(smtpPluginManifest);

} // namespace ipxp
