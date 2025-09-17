/**
 * @file
 * @brief Plugin for parsing HTTP traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts HTTP data from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "http.hpp"

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <ranges>
#include <utils/stringViewUtils.hpp>
#include <utils/spanUtils.hpp>

#include "httpParser.hpp"

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

static FieldSchema createHTTPSchema(FieldManager& fieldManager, FieldHandlers<HTTPFields>& handlers)
{
	FieldSchema schema = fieldManager.createFieldSchema("http");

	handlers.insert(HTTPFields::HTTP_REQUEST_METHOD, schema.addScalarField(
		"HTTP_REQUEST_METHOD",
		[](const void* context) { return toStringView(reinterpret_cast<const HTTPData*>(context)->method); }
	));
	handlers.insert(HTTPFields::HTTP_REQUEST_HOST, schema.addScalarField(
		"HTTP_REQUEST_HOST",
		[](const void* context) { return toStringView(reinterpret_cast<const HTTPData*>(context)->host); }
	));
	handlers.insert(HTTPFields::HTTP_REQUEST_URL, schema.addScalarField(
		"HTTP_REQUEST_URL",
		[](const void* context) { return toStringView(reinterpret_cast<const HTTPData*>(context)->uri); }
	));
	handlers.insert(HTTPFields::HTTP_REQUEST_AGENT, schema.addScalarField(
		"HTTP_REQUEST_AGENT",
		[](const void* context) { return toStringView(reinterpret_cast<const HTTPData*>(context)->userAgent); }
	));
	handlers.insert(HTTPFields::HTTP_REQUEST_REFERER, schema.addScalarField(
		"HTTP_REQUEST_REFERER",
		[](const void* context) { return toStringView(reinterpret_cast<const HTTPData*>(context)->referer); }
	));
	handlers.insert(HTTPFields::HTTP_RESPONSE_STATUS_CODE, schema.addScalarField(
		"HTTP_RESPONSE_STATUS_CODE",
		[](const void* context) { return reinterpret_cast<const HTTPData*>(context)->statusCode; }
	));
	handlers.insert(HTTPFields::HTTP_RESPONSE_CONTENT_TYPE, schema.addScalarField(
		"HTTP_RESPONSE_CONTENT_TYPE",
		[](const void* context) { return toStringView(reinterpret_cast<const HTTPData*>(context)->contentType); }
	));
	handlers.insert(HTTPFields::HTTP_RESPONSE_SERVER, schema.addScalarField(
		"HTTP_RESPONSE_SERVER",
		[](const void* context) { return toStringView(reinterpret_cast<const HTTPData*>(context)->server); }
	));
	handlers.insert(HTTPFields::HTTP_RESPONSE_SET_COOKIE_NAMES, schema.addScalarField(
		"HTTP_RESPONSE_SET_COOKIE_NAMES",
		[](const void* context) { return toStringView(reinterpret_cast<const HTTPData*>(context)->cookies); }
	));

	return schema;
}

HTTPPlugin::HTTPPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createHTTPSchema(manager, m_fieldHandlers);
}

PluginUpdateResult HTTPPlugin::parseHTTP(
	std::span<const std::byte> payload, FlowRecord& flowRecord, HTTPData& httpData) noexcept
{
	HTTPParser parser;
	parser.parse(payload);

	if (parser.requestParsed && httpData.requestParsed) {
		// Must be flush and reinsert ????
		return {
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::Flush,
		};
	}
	httpData.requestParsed |= parser.requestParsed;

	if (parser.responseParsed && httpData.responseParsed) {
		// Must be flush and reinsert ????
		return {
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::Flush,
		};
	}
	httpData.responseParsed |= parser.responseParsed;

	if (parser.method.has_value()) {
		std::ranges::copy(*parser.method |
			std::views::take(httpData.method.capacity()),
		std::back_inserter(httpData.method));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_METHOD].setAsAvailable(flowRecord);
	}
	if (parser.uri.has_value()) {
		std::ranges::copy(*parser.uri |
			std::views::take(httpData.uri.capacity()),
		std::back_inserter(httpData.uri));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_URL].setAsAvailable(flowRecord);
	}
	if (parser.host.has_value()) {
		std::ranges::copy(*parser.host |
			std::views::take(httpData.host.capacity()),
		std::back_inserter(httpData.host));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_HOST].setAsAvailable(flowRecord);
	}
	if (parser.userAgent.has_value()) {
		std::ranges::copy(*parser.userAgent |
			std::views::take(httpData.userAgent.capacity()),
		std::back_inserter(httpData.userAgent));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_AGENT].setAsAvailable(flowRecord);
	}
	if (parser.referer.has_value()) {
		std::ranges::copy(*parser.referer |
			std::views::take(httpData.referer.capacity()),
		std::back_inserter(httpData.referer));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_REFERER].setAsAvailable(flowRecord);
	}
	if (parser.statusCode.has_value()) {
		httpData.statusCode = *parser.statusCode;
		m_fieldHandlers[HTTPFields::HTTP_RESPONSE_STATUS_CODE].setAsAvailable(flowRecord);
	}
	if (parser.contentType.has_value()) {
		std::ranges::copy(*parser.contentType |
			std::views::take(httpData.contentType.capacity()),
		std::back_inserter(httpData.contentType));
		m_fieldHandlers[HTTPFields::HTTP_RESPONSE_CONTENT_TYPE].setAsAvailable(flowRecord);
	}
	if (parser.server.has_value()) {
		std::ranges::copy(*parser.server |
			std::views::take(httpData.server.capacity()),
		std::back_inserter(httpData.server));
		m_fieldHandlers[HTTPFields::HTTP_RESPONSE_SERVER].setAsAvailable(flowRecord);
	}
	if (parser.cookies.has_value()) {
		std::ranges::for_each(*parser.cookies, [&](std::string_view cookie) {
			std::ranges::copy(cookie |
				std::views::take(
					httpData.cookies.capacity() - httpData.cookies.size()),
			std::back_inserter(httpData.cookies));
			if (httpData.cookies.size() != httpData.cookies.capacity()) {
				httpData.cookies.push_back(';');
			}
		});
		m_fieldHandlers[HTTPFields::HTTP_RESPONSE_SET_COOKIE_NAMES].setAsAvailable(flowRecord);
	}


	if (httpData.requestParsed && httpData.responseParsed) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginInitResult HTTPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<HTTPData*>(pluginContext));
	auto [updateRequirement, flowAction] = parseHTTP(
		toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len), flowContext.flowRecord, *pluginData);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = updateRequirement,
		.flowAction = flowAction,
	};
}

PluginUpdateResult HTTPPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<HTTPData*>(pluginContext);
	return parseHTTP(
		toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len), flowContext.flowRecord, *pluginData);
}

void HTTPPlugin::onDestroy(void* pluginContext) 
{
	std::destroy_at(reinterpret_cast<HTTPData*>(pluginContext));
}

PluginDataMemoryLayout HTTPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(HTTPData),
		.alignment = alignof(HTTPData),
	};
}

static const PluginRegistrar<HTTPPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	httpPluginRegistrar(httpPluginManifest);

} // namespace ipxp
