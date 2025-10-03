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

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <readers/headerFieldReader/headerFieldReader.hpp>
#include <utils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp {

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
		schema.addScalarField("SSDP_LOCATION_PORT", [](const void* context) {
			return reinterpret_cast<const SSDPData*>(context)->port;
		}));
	handlers.insert(SSDPFields::SSDP_NT, schema.addScalarField("SSDP_NT", [](const void* context) {
		return toStringView(reinterpret_cast<const SSDPData*>(context)->notificationType);
	}));
	handlers.insert(
		SSDPFields::SSDP_SERVER,
		schema.addScalarField("SSDP_SERVER", [](const void* context) {
			return toStringView(reinterpret_cast<const SSDPData*>(context)->server);
		}));
	handlers.insert(SSDPFields::SSDP_ST, schema.addScalarField("SSDP_ST", [](const void* context) {
		return toStringView(reinterpret_cast<const SSDPData*>(context)->searchTarget);
	}));
	handlers.insert(
		SSDPFields::SSDP_USER_AGENT,
		schema.addScalarField("SSDP_USER_AGENT", [](const void* context) {
			return toStringView(reinterpret_cast<const SSDPData*>(context)->userAgent);
		}));

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
	SSDPData& pluginData,
	FlowRecord& flowRecord) noexcept
{
	HeaderFieldReader reader;

	for (const auto& [key, value] : reader.getRange(headerFields)) {
		if (key == "NT") {
			getURN(value, pluginData.notificationType);
			m_fieldHandlers[SSDPFields::SSDP_NT].setAsAvailable(flowRecord);
		}

		if (key == "LOCATION") {
			const std::optional<uint16_t> port = parseLocationPort(value);
			if (port.has_value()) {
				pluginData.port = *port;
				m_fieldHandlers[SSDPFields::SSDP_LOCATION_PORT].setAsAvailable(flowRecord);
			}
		}

		if (key == "SERVER") {
			std::ranges::copy(
				value | std::views::take(pluginData.server.capacity() - pluginData.server.size()),
				std::back_inserter(pluginData.server));
			m_fieldHandlers[SSDPFields::SSDP_SERVER].setAsAvailable(flowRecord);
		}
	}
}

void SSDPPlugin::parseSSDPMSearch(
	std::string_view headerFields,
	SSDPData& pluginData,
	FlowRecord& flowRecord) noexcept
{
	HeaderFieldReader reader;

	for (const auto& [key, value] : reader.getRange(headerFields)) {
		if (key == "ST") {
			getURN(value, pluginData.searchTarget);
			m_fieldHandlers[SSDPFields::SSDP_ST].setAsAvailable(flowRecord);
		}

		if (key == "USER_AGENT") {
			std::ranges::copy(
				value
					| std::views::take(
						pluginData.userAgent.capacity() - pluginData.userAgent.size()),
				std::back_inserter(pluginData.userAgent));
			m_fieldHandlers[SSDPFields::SSDP_USER_AGENT].setAsAvailable(flowRecord);
		}
	}
}

constexpr void SSDPPlugin::parseSSDP(
	std::string_view payload,
	SSDPData& pluginData,
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
		parseSSDPNotify(headerFields, pluginData, flowRecord);
	}

	if (toStringView(payload).starts_with("M-SEARCH")) {
		parseSSDPMSearch(headerFields, pluginData, flowRecord);
	}
}

PluginInitResult SSDPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr std::size_t SSDP_PORT = 1900;
	if (flowContext.packet.dst_port != SSDP_PORT) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<SSDPData*>(pluginContext));
	parseSSDP(
		toStringView(flowContext.packet.payload, flowContext.packet.payload_len),
		*pluginData,
		flowContext.flowRecord);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult SSDPPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<SSDPData*>(pluginContext);
	constexpr std::size_t SSDP_PORT = 1900;
	if (flowContext.packet.dst_port == SSDP_PORT) {
		parseSSDP(
			toStringView(flowContext.packet.payload, flowContext.packet.payload_len),
			*pluginData,
			flowContext.flowRecord);
	}

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

void SSDPPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<SSDPData*>(pluginContext));
}

PluginDataMemoryLayout SSDPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(SSDPData),
		.alignment = alignof(SSDPData),
	};
}

static const PluginRegistrar<
	SSDPPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ssdpRegistrar(ssdpPluginManifest);

} // namespace ipxp
