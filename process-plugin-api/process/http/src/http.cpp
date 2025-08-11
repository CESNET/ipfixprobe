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

#include "http.hpp"

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

namespace ipxp {

static const PluginManifest httpPluginManifest = {
	.name = "http",
	.description = "http process plugin for parsing http traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("http", "Parse HTTP traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<HTTPFields>> fields = {
	{HTTPFields::HTTP_REQUEST_METHOD, "HTTP_REQUEST_METHOD"},
	{HTTPFields::HTTP_REQUEST_HOST, "HTTP_REQUEST_HOST"},
	{HTTPFields::HTTP_REQUEST_URL, "HTTP_REQUEST_URL"},
	{HTTPFields::HTTP_REQUEST_AGENT, "HTTP_REQUEST_AGENT"},
	{HTTPFields::HTTP_REQUEST_REFERER, "HTTP_REQUEST_REFERER"},
	{HTTPFields::HTTP_RESPONSE_STATUS_CODE, "HTTP_RESPONSE_STATUS_CODE"},
	{HTTPFields::HTTP_RESPONSE_CONTENT_TYPE, "HTTP_RESPONSE_CONTENT_TYPE"},
	{HTTPFields::HTTP_RESPONSE_SERVER, "HTTP_RESPONSE_SERVER"},
	{HTTPFields::HTTP_RESPONSE_SET_COOKIE_NAMES, "HTTP_RESPONSE_SET_COOKIE_NAMES"},
};


static FieldSchema createHTTPSchema()
{
	FieldSchema schema("http");

	return schema;
}

HTTPPlugin::HTTPPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createHTTPSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

constexpr
FlowAction HTTPPlugin::parseHTTP(
	std::span<const std::byte> payload, FlowRecord& flowRecord) noexcept
{
	HTTPParser parser;
	parser.parse(payload);

	if (parser.requestParsed && m_requestParsed) {
		return FlowAction::FlushWithReinsert;
	}
	if (parser.responseParsed && m_responseParsed) {
		return FlowAction::FlushWithReinsert;
	}

	if (parser.method.has_value()) {
		std::ranges::copy(*parser.method |
			std::views::take(m_exportData.method.capacity()),
		std::back_inserter(m_exportData.method));
	}
	if (parser.uri.has_value()) {
		std::ranges::copy(*parser.uri |
			std::views::take(m_exportData.uri.capacity()),
		std::back_inserter(m_exportData.uri));
	}
	if (parser.host.has_value()) {
		std::ranges::copy(*parser.host |
			std::views::take(m_exportData.host.capacity()),
		std::back_inserter(m_exportData.host));
	}
	if (parser.userAgent.has_value()) {
		std::ranges::copy(*parser.userAgent |
			std::views::take(m_exportData.userAgent.capacity()),
		std::back_inserter(m_exportData.userAgent));
	}
	if (parser.referer.has_value()) {
		std::ranges::copy(*parser.referer |
			std::views::take(m_exportData.referer.capacity()),
		std::back_inserter(m_exportData.referer));
	}
	if (parser.statusCode.has_value()) {
		m_exportData.statusCode = *parser.statusCode;
	}
	if (parser.contentType.has_value()) {
		std::ranges::copy(*parser.contentType |
			std::views::take(m_exportData.contentType.capacity()),
		std::back_inserter(m_exportData.contentType));
	}
	if (parser.server.has_value()) {
		std::ranges::copy(*parser.server |
			std::views::take(m_exportData.server.capacity()),
		std::back_inserter(m_exportData.server));
	}
	if (parser.cookies.has_value()) {
		std::ranges::copy(*parser.cookies |
			std::views::take(m_exportData.cookies.capacity()),
		std::back_inserter(m_exportData.cookies));
	}

	if (m_requestParsed && m_responseParsed) {
		return FlowAction::RequestNoData;
	}

	return FlowAction::RequestFullData;
}

FlowAction HTTPPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	return parseHTTP(packet.payload, flowRecord);
}

FlowAction HTTPPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	return parseHTTP(packet.payload, flowRecord);
}

void HTTPPlugin::onFlowExport(FlowRecord& flowRecord) 
{		
}

ProcessPlugin* HTTPPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<HTTPPlugin*>(constructAtAddress), *this);
}

std::string HTTPPlugin::getName() const { 
	return httpPluginManifest.name; 
}

const void* HTTPPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<HTTPPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	httpPluginRegistrar(httpPluginManifest);

} // namespace ipxp
