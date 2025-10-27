/**
 * @file
 * @brief Plugin for parsing RTSP traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses RTSP traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "rtsp.hpp"

#include "rtspExtensionReader.hpp"
#include "rtspGetters.hpp"

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

using namespace std::literals::string_view_literals;

namespace ipxp::process::rtsp {

static const PluginManifest rtspPluginManifest = {
	.name = "rtsp",
	.description = "Rtsp process plugin for parsing rtsp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("rtsp", "Parse RTSP traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createRTSPSchema(FieldManager& fieldManager, FieldHandlers<RTSPFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("rtsp");

	handlers.insert(
		RTSPFields::RTSP_REQUEST_METHOD,
		schema.addScalarField("RTSP_REQUEST_METHOD", getRTSPRequestMethodField));

	handlers.insert(
		RTSPFields::RTSP_REQUEST_AGENT,
		schema.addScalarField("RTSP_REQUEST_AGENT", getRTSPRequestAgentField));

	handlers.insert(
		RTSPFields::RTSP_REQUEST_URI,
		schema.addScalarField("RTSP_REQUEST_URI", getRTSPRequestURIField));

	handlers.insert(
		RTSPFields::RTSP_RESPONSE_STATUS_CODE,
		schema.addScalarField("RTSP_RESPONSE_STATUS_CODE", getRTSPResponseStatusCodeField));

	handlers.insert(
		RTSPFields::RTSP_RESPONSE_SERVER,
		schema.addScalarField("RTSP_RESPONSE_SERVER", getRTSPResponseServerField));

	handlers.insert(
		RTSPFields::RTSP_RESPONSE_CONTENT_TYPE,
		schema.addScalarField("RTSP_RESPONSE_CONTENT_TYPE", getRTSPResponseContentTypeField));

	return schema;
}

RTSPPlugin::RTSPPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createRTSPSchema(manager, m_fieldHandlers);
}

bool RTSPPlugin::parseRequest(std::string_view payload, RTSPContext& rtspContext) noexcept
{
	/* Request line:
	 *
	 * METHOD URI VERSION
	 * |     |   |
	 * |     |   -------- end
	 * |     ------------ begin
	 * ----- ------------ data
	 */

	/* Find begin of URI. */
	const std::size_t uriBegin = payload.find(' ');
	if (uriBegin == std::string_view::npos) {
		return false;
	}

	/* Find end of URI. */
	const std::size_t uriEnd = payload.find(' ', uriBegin + 1);
	if (uriEnd == std::string_view::npos) {
		// request is fragmented
		return false;
	}

	if (payload.substr(uriEnd, 4) != "RTSP") {
		return false;
	}

	std::string_view method = payload.substr(0, uriBegin).substr(0, rtspContext.method.capacity());
	rtspContext.method.assign(method.begin(), method.end());

	std::string_view uri
		= payload.substr(uriBegin + 1, uriEnd - uriBegin - 1).substr(0, rtspContext.uri.capacity());
	rtspContext.uri.assign(uri.begin(), uri.end());

	const std::size_t requestLineEnd = payload.find('\n', uriEnd + 1);
	if (requestLineEnd == std::string_view::npos) {
		return false;
	}

	const std::size_t requestFieldBegin = requestLineEnd + 1;
	if (requestFieldBegin == std::string_view::npos) {
		return false;
	}

	/* Header:
	 *
	 * REQ-FIELD: VALUE
	 * |        |      |
	 * |        |      ----- end
	 * |        ------------ keyval_delimiter
	 * --------------------- begin
	 */

	/* Process headers. */
	RTSPExtensionReader reader;
	std::ranges::for_each(
		reader.getRange(payload.substr(requestFieldBegin)),
		[&](const Extension& extension) {
			if (extension.key == "User-Agent") {
				std::string_view userAgent = extension.value.substr(
					0,
					rtspContext.userAgent.capacity() - rtspContext.userAgent.size());
				rtspContext.userAgent.assign(userAgent.begin(), userAgent.end());
			}
		});

	rtspContext.processingState.requestParsed = true;

	return true;
}

constexpr static bool isRequest(std::string_view payload) noexcept
{
	constexpr auto rtspMethods = std::to_array<std::string_view>(
		{"GET ",
		 "POST",
		 "PUT ",
		 "HEAD",
		 "DELE",
		 "TRAC",
		 "OPTI",
		 "CONN",
		 "PATC",
		 "DESC",
		 "SETU",
		 "PLAY",
		 "PAUS",
		 "TEAR",
		 "RECO",
		 "ANNO"});
	return payload.size() >= 4 && std::ranges::any_of(rtspMethods, [&](std::string_view method) {
			   return payload.starts_with(method);
		   });
}

constexpr static bool isResponse(std::string_view payload) noexcept
{
	return payload.starts_with("RTSP");
}

bool RTSPPlugin::parseResponse(std::string_view payload, RTSPContext& rtspContext) noexcept
{
	/* Response line:
	 *
	 * VERSION CODE REASON
	 * |      |    |
	 * |      |    --------- end
	 * |      -------------- begin
	 * --------------------- data
	 */

	/* Find begin of status code. */
	const std::size_t versionEnd = payload.find(' ');
	if (versionEnd == std::string_view::npos) {
		return false;
	}

	const std::size_t statusBegin = versionEnd + 1;
	if (statusBegin == payload.size()) {
		return false;
	}

	const std::size_t statusEnd = payload.find(' ', statusBegin + 1);
	if (statusEnd == std::string_view::npos) {
		return false;
	}

	/* Copy and check RTSP response code. */
	if (std::from_chars(payload.data() + statusBegin, payload.data() + statusEnd, rtspContext.code)
			.ec
		== std::errc()) {
		return false;
	}

	const std::size_t lineEnd = payload.find('\n', statusEnd + 1);
	if (lineEnd == std::string_view::npos) {
		return false;
	}

	RTSPExtensionReader reader;
	std::ranges::for_each(
		reader.getRange(payload.substr(lineEnd + 1)),
		[&](const Extension& extension) {
			if (extension.key == "Content-Type") {
				rtspContext.contentType.assign(extension.value.begin(), extension.value.end());
			}
			if (extension.key == "Server") {
				rtspContext.server.assign(extension.value.begin(), extension.value.end());
			}
		});

	rtspContext.processingState.responseParsed = true;

	return true;
}

OnUpdateResult
RTSPPlugin::updateExportData(std::string_view payload, RTSPContext& rtspContext) noexcept
{
	if (isRequest(payload) && !parseRequest(payload, rtspContext)) {
		return OnUpdateResult::Remove;
	}

	if (isResponse(payload) && !parseResponse(payload, rtspContext)) {
		return OnUpdateResult::Remove;
	}

	return OnUpdateResult::Final;
}

OnInitResult RTSPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	std::string_view payloadView = toStringView(getPayload(*flowContext.packetContext.packet));
	if (!isRequest(payloadView) && !isResponse(payloadView)) {
		return OnInitResult::Irrelevant;
	}

	auto& rtspContext = *std::construct_at(reinterpret_cast<RTSPContext*>(pluginContext));
	const OnUpdateResult updateRequirement = updateExportData(payloadView, rtspContext);

	return updateRequirement == OnUpdateResult::Remove ? OnInitResult::ConstructedNeedsUpdate
													   : OnInitResult::ConstructedFinal;
}

BeforeUpdateResult
RTSPPlugin::beforeUpdate(const FlowContext& flowContext, const void* pluginContext) const
{
	auto& rtspContext = *reinterpret_cast<const RTSPContext*>(pluginContext);
	std::string_view payload = toStringView(getPayload(*flowContext.packetContext.packet));

	if (isRequest(payload) && rtspContext.processingState.requestParsed) {
		return BeforeUpdateResult::FlushFlowAndReinsert;
	}

	if (isResponse(payload) && rtspContext.processingState.responseParsed) {
		return BeforeUpdateResult::FlushFlowAndReinsert;
	}

	return BeforeUpdateResult::NoAction;
}

OnUpdateResult RTSPPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& rtspContext = *reinterpret_cast<RTSPContext*>(pluginContext);
	return updateExportData(
		toStringView(getPayload(*flowContext.packetContext.packet)),
		rtspContext);
}

void RTSPPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<RTSPContext*>(pluginContext));
}

PluginDataMemoryLayout RTSPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(RTSPContext),
		.alignment = alignof(RTSPContext),
	};
}

static const PluginRegistrar<
	RTSPPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	rtspRegistrar(rtspPluginManifest);

} // namespace ipxp::process::rtsp
