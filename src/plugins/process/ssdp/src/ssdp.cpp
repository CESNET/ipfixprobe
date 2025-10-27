/**
 * @file
 * @brief Plugin for parsing ssdp traffic.
 * @author Ondrej Sedlacek xsedla1o@stud.fit.vutbr.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses SSDP traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "ssdp.hpp"

#include "ssdpGetters.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <readers/headerFieldReader/headerFieldReader.hpp>
#include <utils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::ssdp {

static const PluginManifest ssdpPluginManifest = {
	.name = "ssdp",
	.description = "Ssdp process plugin for parsing ssdp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("ssdp", "Parse SSDP traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createSSDPSchema(FieldManager& fieldManager, FieldHandlers<SSDPFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("ssdp");

	handlers.insert(
		SSDPFields::SSDP_LOCATION_PORT,
		schema.addScalarField("SSDP_LOCATION_PORT", getSSDPLocationPortField));
	handlers.insert(SSDPFields::SSDP_NT, schema.addScalarField("SSDP_NT", getSSDPNTField));
	handlers.insert(
		SSDPFields::SSDP_SERVER,
		schema.addScalarField("SSDP_SERVER", getSSDPServerField));
	handlers.insert(
		SSDPFields::SSDP_ST,
		schema.addScalarField("SSDP_ST", getSSDPSearchTargetField));
	handlers.insert(
		SSDPFields::SSDP_USER_AGENT,
		schema.addScalarField("SSDP_USER_AGENT", getSSDPUserAgentField));

	return schema;
}

SSDPPlugin::SSDPPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createSSDPSchema(manager, m_fieldHandlers);
}

constexpr static void getURN(std::string_view value, auto&& output) noexcept
{
	const std::vector<std::string_view> tokens = splitToVector(value);
	if (tokens.size() < 2 || tokens[0] != "urn") {
		return;
	}

	std::ranges::copy(
		tokens[1] | std::views::take(output.capacity() - output.size()),
		std::back_inserter(output));
}

constexpr static std::optional<uint16_t> parseLocationPort(std::string_view value) noexcept
{
	const std::size_t protocolPos = value.find("://");
	if (protocolPos == std::string_view::npos) {
		return std::nullopt;
	}

	const std::size_t portPos = value.find(':', protocolPos + 3);
	if (portPos == std::string_view::npos) {
		return std::nullopt;
	}

	const std::string_view portView = value.substr(portPos + 1);
	uint16_t port;
	if (std::from_chars(portView.begin(), portView.end(), port).ec != std::errc()) {
		return std::nullopt;
	}

	return port;
}

void SSDPPlugin::parseSSDPNotify(
	std::string_view headerFields,
	SSDPContext& ssdpContext,
	FlowRecord& flowRecord) noexcept
{
	HeaderFieldReader reader;

	for (const auto& [key, value] : reader.getRange(headerFields)) {
		if (key == "NT") {
			getURN(value, ssdpContext.notificationType);
			m_fieldHandlers[SSDPFields::SSDP_NT].setAsAvailable(flowRecord);
		}

		if (key == "LOCATION") {
			const std::optional<uint16_t> port = parseLocationPort(value);
			if (port.has_value()) {
				ssdpContext.port = *port;
				m_fieldHandlers[SSDPFields::SSDP_LOCATION_PORT].setAsAvailable(flowRecord);
			}
		}

		if (key == "SERVER") {
			std::ranges::copy(
				value | std::views::take(ssdpContext.server.capacity() - ssdpContext.server.size()),
				std::back_inserter(ssdpContext.server));
			m_fieldHandlers[SSDPFields::SSDP_SERVER].setAsAvailable(flowRecord);
		}
	}
}

void SSDPPlugin::parseSSDPMSearch(
	std::string_view headerFields,
	SSDPContext& ssdpContext,
	FlowRecord& flowRecord) noexcept
{
	HeaderFieldReader reader;

	for (const auto& [key, value] : reader.getRange(headerFields)) {
		if (key == "ST") {
			getURN(value, ssdpContext.searchTarget);
			m_fieldHandlers[SSDPFields::SSDP_ST].setAsAvailable(flowRecord);
		}

		if (key == "USER_AGENT") {
			std::ranges::copy(
				value
					| std::views::take(
						ssdpContext.userAgent.capacity() - ssdpContext.userAgent.size()),
				std::back_inserter(ssdpContext.userAgent));
			m_fieldHandlers[SSDPFields::SSDP_USER_AGENT].setAsAvailable(flowRecord);
		}
	}
}

constexpr void SSDPPlugin::parseSSDP(
	std::string_view payload,
	SSDPContext& ssdpContext,
	FlowRecord& flowRecord) noexcept
{
	if (payload.empty()) {
		return;
	}

	auto headerEnd = payload.find('\n');
	if (headerEnd == std::string_view::npos) {
		return;
	}

	std::string_view headerFields = payload.substr(headerEnd + 1);

	if (toStringView(payload).starts_with("NOTIFY")) {
		parseSSDPNotify(headerFields, ssdpContext, flowRecord);
	}

	if (toStringView(payload).starts_with("M-SEARCH")) {
		parseSSDPMSearch(headerFields, ssdpContext, flowRecord);
	}
}

OnInitResult SSDPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr std::size_t SSDP_PORT = 1900;
	if (flowContext.flowRecord.flowKey.dstPort != SSDP_PORT) {
		return OnInitResult::Irrelevant;
	}

	auto& ssdpContext = *std::construct_at(reinterpret_cast<SSDPContext*>(pluginContext));
	parseSSDP(
		toStringView(getPayload(*flowContext.packetContext.packet)),
		ssdpContext,
		flowContext.flowRecord);

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult SSDPPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& ssdpContext = *reinterpret_cast<SSDPContext*>(pluginContext);
	constexpr std::size_t SSDP_PORT = 1900;
	if (getDstPort(flowContext.flowRecord, flowContext.packetDirection) == SSDP_PORT) {
		parseSSDP(
			toStringView(getPayload(*flowContext.packetContext.packet)),
			ssdpContext,
			flowContext.flowRecord);
	}

	return OnUpdateResult::NeedsUpdate;
}

void SSDPPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<SSDPContext*>(pluginContext));
}

PluginDataMemoryLayout SSDPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(SSDPContext),
		.alignment = alignof(SSDPContext),
	};
}

static const PluginRegistrar<
	SSDPPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ssdpRegistrar(ssdpPluginManifest);

} // namespace ipxp::process::ssdp
