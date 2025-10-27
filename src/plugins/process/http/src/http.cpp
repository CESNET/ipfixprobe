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

#include "httpGetters.hpp"

#include <ranges>

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

namespace ipxp::process::http {

static const PluginManifest httpPluginManifest = {
	.name = "http",
	.description = "http process plugin for parsing http traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("http", "Parse HTTP traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup createHTTPSchema(FieldManager& fieldManager, FieldHandlers<HTTPFields>& handlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("http");

	handlers.insert(
		HTTPFields::HTTP_REQUEST_METHOD,
		schema.addScalarField("HTTP_REQUEST_METHOD", getHTTPMethodField));
	handlers.insert(
		HTTPFields::HTTP_REQUEST_HOST,
		schema.addScalarField("HTTP_REQUEST_HOST", getHTTPHostField));
	handlers.insert(
		HTTPFields::HTTP_REQUEST_URL,
		schema.addScalarField("HTTP_REQUEST_URL", getHTTPURLField));
	handlers.insert(
		HTTPFields::HTTP_REQUEST_AGENT,
		schema.addScalarField("HTTP_REQUEST_AGENT", getHTTPUserAgentField));
	handlers.insert(
		HTTPFields::HTTP_REQUEST_REFERER,
		schema.addScalarField("HTTP_REQUEST_REFERER", getHTTPRefererField));
	handlers.insert(
		HTTPFields::HTTP_RESPONSE_STATUS_CODE,
		schema.addScalarField("HTTP_RESPONSE_STATUS_CODE", getHTTPStatusCodeField));
	handlers.insert(
		HTTPFields::HTTP_RESPONSE_CONTENT_TYPE,
		schema.addScalarField("HTTP_RESPONSE_CONTENT_TYPE", getHTTPContentTypeField));
	handlers.insert(
		HTTPFields::HTTP_RESPONSE_SERVER,
		schema.addScalarField("HTTP_RESPONSE_SERVER", getHTTPServerField));
	handlers.insert(
		HTTPFields::HTTP_RESPONSE_SET_COOKIE_NAMES,
		schema.addScalarField("HTTP_RESPONSE_SET_COOKIE_NAMES", getHTTPCookiesField));

	return schema;
}

HTTPPlugin::HTTPPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createHTTPSchema(manager, m_fieldHandlers);
}

void HTTPPlugin::saveParsedValues(
	const HTTPParser& parser,
	FlowRecord& flowRecord,
	HTTPContext& httpContext) noexcept
{
	httpContext.requestParsed |= parser.requestParsed;
	httpContext.responseParsed |= parser.responseParsed;

	if (parser.method.has_value()) {
		std::ranges::copy(
			*parser.method | std::views::take(httpContext.method.capacity()),
			std::back_inserter(httpContext.method));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_METHOD].setAsAvailable(flowRecord);
	}
	if (parser.uri.has_value()) {
		std::ranges::copy(
			*parser.uri | std::views::take(httpContext.uri.capacity()),
			std::back_inserter(httpContext.uri));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_URL].setAsAvailable(flowRecord);
	}
	if (parser.host.has_value()) {
		std::ranges::copy(
			*parser.host | std::views::take(httpContext.host.capacity()),
			std::back_inserter(httpContext.host));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_HOST].setAsAvailable(flowRecord);
	}
	if (parser.userAgent.has_value()) {
		std::ranges::copy(
			*parser.userAgent | std::views::take(httpContext.userAgent.capacity()),
			std::back_inserter(httpContext.userAgent));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_AGENT].setAsAvailable(flowRecord);
	}
	if (parser.referer.has_value()) {
		std::ranges::copy(
			*parser.referer | std::views::take(httpContext.referer.capacity()),
			std::back_inserter(httpContext.referer));
		m_fieldHandlers[HTTPFields::HTTP_REQUEST_REFERER].setAsAvailable(flowRecord);
	}
	if (parser.statusCode.has_value()) {
		httpContext.statusCode = *parser.statusCode;
		m_fieldHandlers[HTTPFields::HTTP_RESPONSE_STATUS_CODE].setAsAvailable(flowRecord);
	}
	if (parser.contentType.has_value()) {
		std::ranges::copy(
			*parser.contentType | std::views::take(httpContext.contentType.capacity()),
			std::back_inserter(httpContext.contentType));
		m_fieldHandlers[HTTPFields::HTTP_RESPONSE_CONTENT_TYPE].setAsAvailable(flowRecord);
	}
	if (parser.server.has_value()) {
		std::ranges::copy(
			*parser.server | std::views::take(httpContext.server.capacity()),
			std::back_inserter(httpContext.server));
		m_fieldHandlers[HTTPFields::HTTP_RESPONSE_SERVER].setAsAvailable(flowRecord);
	}
	if (parser.cookies.has_value()) {
		std::ranges::for_each(*parser.cookies, [&](std::string_view cookie) {
			std::ranges::copy(
				cookie
					| std::views::take(httpContext.cookies.capacity() - httpContext.cookies.size()),
				std::back_inserter(httpContext.cookies));
			if (httpContext.cookies.size() != httpContext.cookies.capacity()) {
				httpContext.cookies.push_back(';');
			}
		});
		m_fieldHandlers[HTTPFields::HTTP_RESPONSE_SET_COOKIE_NAMES].setAsAvailable(flowRecord);
	}
}

OnInitResult HTTPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	HTTPParser parser;
	parser.parse(getPayload(*flowContext.packetContext.packet));
	if (!parser.method.has_value()) {
		return OnInitResult::PendingConstruction;
	}

	auto& httpContext = *std::construct_at(reinterpret_cast<HTTPContext*>(pluginContext));
	saveParsedValues(parser, flowContext.flowRecord, httpContext);

	return OnInitResult::ConstructedNeedsUpdate;
}

BeforeUpdateResult
HTTPPlugin::beforeUpdate(const FlowContext& flowContext, const void* pluginContext) const
{
	auto& httpContext = *reinterpret_cast<const HTTPContext*>(pluginContext);

	HTTPParser parser;
	parser.parse(getPayload(*flowContext.packetContext.packet));
	if (parser.requestParsed && httpContext.requestParsed) {
		return BeforeUpdateResult::FlushFlowAndReinsert;
	}

	if (parser.responseParsed && httpContext.responseParsed) {
		return BeforeUpdateResult::FlushFlowAndReinsert;
	}

	return BeforeUpdateResult::NoAction;
}

OnUpdateResult HTTPPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& httpContext = *reinterpret_cast<HTTPContext*>(pluginContext);
	HTTPParser parser;
	parser.parse(getPayload(*flowContext.packetContext.packet));
	saveParsedValues(parser, flowContext.flowRecord, httpContext);
	if (httpContext.requestParsed && httpContext.responseParsed) {
		return OnUpdateResult::Final;
	}

	return OnUpdateResult::NeedsUpdate;
}

void HTTPPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<HTTPContext*>(pluginContext));
}

PluginDataMemoryLayout HTTPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(HTTPContext),
		.alignment = alignof(HTTPContext),
	};
}

static const PluginRegistrar<
	HTTPPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	httpPluginRegistrar(httpPluginManifest);

} // namespace ipxp::process::http
