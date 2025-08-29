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

#include "rtsp.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

#include "rtspExtensionReader.hpp"

using namespace std::literals::string_view_literals;

namespace ipxp {

static const PluginManifest rtspPluginManifest = {
	.name = "rtsp",
	.description = "Rtsp process plugin for parsing rtsp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("rtsp", "Parse RTSP traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<RTSPFields>> fields = {
	{RTSPFields::RTSP_REQUEST_METHOD, "RTSP_REQUEST_METHOD"},
	{RTSPFields::RTSP_REQUEST_AGENT, "RTSP_REQUEST_AGENT"},
	{RTSPFields::RTSP_REQUEST_URI, "RTSP_REQUEST_URI"},
	{RTSPFields::RTSP_RESPONSE_STATUS_CODE, "RTSP_RESPONSE_STATUS_CODE"},
	{RTSPFields::RTSP_RESPONSE_SERVER, "RTSP_RESPONSE_SERVER"},
	{RTSPFields::RTSP_RESPONSE_CONTENT_TYPE, "RTSP_RESPONSE_CONTENT_TYPE"},
};


static FieldSchema createRTSPSchema()
{
	FieldSchema schema("rtsp");
	// TODO export strings 
	return schema;
}

RTSPPlugin::RTSPPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createRTSPSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

constexpr
bool RTSPPlugin::parseRequest(std::string_view payload) noexcept
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


	std::string_view method 
		= payload.substr(0, uriBegin).substr(0, m_exportData.method.capacity());
	m_exportData.method.assign(method.begin(), method.end());

	std::string_view uri = payload.substr(
		uriBegin + 1, uriEnd - uriBegin - 1).substr(0, m_exportData.uri.capacity());
	m_exportData.uri.assign(uri.begin(), uri.end());

	const std::size_t requestLineEnd 
		= payload.find('\n', uriEnd + 1);
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
	std::ranges::for_each(reader.getRange(payload.substr(requestFieldBegin)),
		[this](const Extension& extension) {
			if (extension.key == "User-Agent") {
				std::string_view userAgent = extension.value.substr(
						0, m_exportData.userAgent.capacity() - m_exportData.userAgent.size());
				m_exportData.userAgent.assign(userAgent.begin(), userAgent.end());
			}
		});

	m_requestParsed = true;

	return true;
}

constexpr static
bool isRequest(std::string_view payload) noexcept
{
	constexpr auto rtspMethods = std::to_array<std::string_view>({
		"GET ", "POST", "PUT ", "HEAD", "DELE", "TRAC", "OPTI", "CONN", "PATC",
		"DESC", "SETU", "PLAY", "PAUS", "TEAR", "RECO", "ANNO"});
	return payload.size() >= 4 && std::ranges::any_of(rtspMethods,
		[&](std::string_view method) {
			return payload.starts_with(method);
		});
}

constexpr static
bool isResponse(std::string_view payload) noexcept
{
	return payload.starts_with("RTSP");
}

constexpr
bool RTSPPlugin::parseResponse(std::string_view payload) noexcept
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
	if (std::from_chars(
			payload.data() + statusBegin, 
			payload.data() + statusEnd, 
			m_exportData.code).ec == std::errc()) {
		return false;
	}

	const std::size_t lineEnd = payload.find('\n', statusEnd + 1);
	if (lineEnd == std::string_view::npos) {
		return false;	
	}

	RTSPExtensionReader reader;
	std::ranges::for_each(reader.getRange(payload.substr(lineEnd + 1)),
		[this](const Extension& extension) {
			if (extension.key == "Content-Type") {
				m_exportData.contentType.assign(
					extension.value.begin(),
					extension.value.end());
			}
			if (extension.key == "Server") {
				m_exportData.server.assign(
					extension.value.begin(),
					extension.value.end());
			}
		});

	m_responseParsed = true;

	return true;
}

constexpr
FlowAction RTSPPlugin::updateExportData(
	std::span<const std::byte> payload) noexcept
{
	std::string_view payloadView = {
		reinterpret_cast<const char*>(payload.data()), payload.size()};
	if (isRequest(payloadView)) {
		if (m_requestParsed) {
			return FlowAction::FlushAndReinsert;
		}
		if (!parseRequest(payloadView)) {
			return FlowAction::RequestNoData;
		}
	}

	if (isResponse(payloadView)) {
		if (m_responseParsed) {
			return FlowAction::FlushAndReinsert;
		}
		if (!parseResponse(payloadView)) {
			return FlowAction::RequestNoData;
		}
	}

	return FlowAction::RequestNoData;
}

FlowAction RTSPPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	return updateExportData(packet.payload);
}


FlowAction RTSPPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	return updateExportData(packet.payload);
}

ProcessPlugin* RTSPPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<RTSPPlugin*>(constructAtAddress), *this);
}

std::string RTSPPlugin::getName() const { 
	return rtspPluginManifest.name; 
}

const void* RTSPPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<RTSPPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	rtspRegistrar(rtspPluginManifest);

} // namespace ipxp
