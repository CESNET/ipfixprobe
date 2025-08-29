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

#include "ssdp.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <readers/headerFieldReader/headerFieldReader.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp {

static const PluginManifest ssdpPluginManifest = {
	.name = "ssdp",
	.description = "Ssdp process plugin for parsing ssdp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("ssdp", "Parse SSDP traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<SSDPFields>> fields = {
	{SSDPFields::SSDP_LOCATION_PORT, "SSDP_LOCATION_PORT"},
	{SSDPFields::SSDP_NT, "SSDP_NT"},
	{SSDPFields::SSDP_SERVER, "SSDP_SERVER"},
	{SSDPFields::SSDP_ST, "SSDP_ST"},
	{SSDPFields::SSDP_USER_AGENT, "SSDP_USER_AGENT"},
};


static FieldSchema createSSDPSchema()
{
	FieldSchema schema("ssdp");

	//TODO 
	return schema;
}

SSDPPlugin::SSDPPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createSSDPSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

constexpr static
void getURN(std::string_view value, auto&& output) noexcept
{
	const std::vector<std::string_view> tokens = splitToVector(value);
	if (tokens.size() < 2 || tokens[0] != "urn") {
		return;
	}

	std::ranges::copy(tokens[1] |
		std::views::take(
			output.capacity() - output.size()),
		std::back_inserter(output));
}

constexpr static
std::optional<uint16_t> parseLocationPort(std::string_view value) noexcept
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
	const auto [_, errorCode]
		= std::from_chars(portView.begin(), portView.end(), port);
	if (errorCode != std::errc()) {
		return std::nullopt;
	}

	return port;
}

void SSDPPlugin::parseSSDPNotify(
	std::string_view headerFields, const uint8_t l4Protocol) noexcept
{
	HeaderFieldReader reader;

	for(const auto& [key, value] : reader.getRange(headerFields)) {
		if (key == "NT") {
			getURN(value, m_exportData.notificationType);
		}

		if (key == "LOCATION") {
			const std::optional<uint16_t> port = 
				parseLocationPort(value);
			if (port.has_value()) {
				m_exportData.port = *port;
			}
		}

		if (key == "SERVER") {
			std::ranges::copy(value |
				std::views::take(m_exportData.server.capacity() - m_exportData.server.size()),
				std::back_inserter(m_exportData.server));
		}
	}
}

void SSDPPlugin::parseSSDPMSearch(std::string_view headerFields) noexcept
{
	HeaderFieldReader reader;

	for(const auto& [key, value] : reader.getRange(headerFields)) {
		if (key == "ST") {
			getURN(value, m_exportData.searchTarget);
		}

		if (key == "USER_AGENT") {
			std::ranges::copy(value |
				std::views::take(m_exportData.userAgent.capacity() - m_exportData.userAgent.size()),
				std::back_inserter(m_exportData.userAgent));
		}
	}
}

constexpr
void SSDPPlugin::parseSSDP(std::string_view payload, const uint8_t l4Protocol) noexcept
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
		parseSSDPNotify(headerFields, l4Protocol);
	}
	
	if (toStringView(payload).starts_with("M-SEARCH")) {
		parseSSDPMSearch(headerFields);
	}
}

FlowAction SSDPPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	constexpr std::size_t SSDP_PORT = 1900;
	if (packet.flowKey.dstPort != SSDP_PORT) {
		return FlowAction::RequestNoData;
	}

	parseSSDP(toStringView(packet.payload), packet.flowKey.l4Protocol);

	return FlowAction::RequestTrimmedData;
}

FlowAction SSDPPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	constexpr std::size_t SSDP_PORT = 1900;
	if (packet.flowKey.dstPort == SSDP_PORT) {
		parseSSDP(toStringView(packet.payload), packet.flowKey.l4Protocol);
	}

	return FlowAction::RequestTrimmedData;
}

void SSDPPlugin::onFlowExport(FlowRecord& flowRecord) {
	// TODO makeAllAvailable();
}

ProcessPlugin* SSDPPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<SSDPPlugin*>(constructAtAddress), *this);
}

std::string SSDPPlugin::getName() const {
	return ssdpPluginManifest.name;
}

const void* SSDPPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<SSDPPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ssdpRegistrar(ssdpPluginManifest);

} // namespace ipxp
