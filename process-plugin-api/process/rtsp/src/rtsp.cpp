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
bool RTSPPlugin::parseRequest(std::span<const std::byte> payload) noexcept
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
	auto uriBegin = std::ranges::find(payload, std::byte{' '});
	if (uriBegin == payload.end()) {
		return false;
	}

	/* Find end of URI. */
	auto uriEnd = std::find(std::next(uriBegin), payload.end(), std::byte{' '});
	if (uriEnd == payload.end()) {
		// request is fragmented
		return false;
	}

	if (!std::equal(uriEnd, std::next(uriEnd, 4), std::as_bytes("RTSP"))) {
		return false;
	}

	std::ranges::copy(std::ranges::subrange(payload.data(), uriBegin) |
		std::views::take(m_exportData.method.capacity()),
	std::back_inserter(m_exportData.method));

	std::ranges::copy(std::ranges::subrange(std::next(uriBegin), uriEnd) |
		std::views::take(m_exportData.uri.capacity()),
	std::back_inserter(m_exportData.uri));

	auto requestLineEnd 
		= std::find(std::next(uriEnd), payload.end(), std::byte{'\n'});
	if (requestLineEnd == payload.end()) {
		return false;
	}

	auto requestFieldBegin = std::next(requestLineEnd);
	if (requestFieldBegin == payload.end()) {
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
	RTSPExtensionReader reader(payload.subspan(requestFieldBegin - payload.data()));
	std::ranges::for_each(reader | 
		std::views::transform([](const Extension& extension) {
			if (extension.key == "User-Agent") {
				m_exportData.userAgent.push_back(extension.value);
			}
		}));

	m_requestParsed = true;

	return true;
}

constexpr static
bool isRequest(std::span<const std::byte> payload) noexcept
{
	constexpr auto rtspMethods = std::to_array<std::string_view>({
		"GET ", "POST", "PUT ", "HEAD", "DELE", "TRAC", "OPTI", "CONN", "PATC",
		"DESC", "SETU", "PLAY", "PAUS", "TEAR", "RECO", "ANNO"});
	return payload.size() >= 4 && std::ranges::any_of(rtspMethods |
		std::views::transform(std::string_view method) {
			return std::ranges::equal(
				std::as_bytes(method), payload.subspan(0, 4));
		});
}

constexpr static
bool isResponse(std::span<const std::byte> payload) noexcept
{
	return payload.size() >= 4 && 
		payload.subspan(0, 4) == std::as_bytes("RTSP");
}

constexpr
bool RTSPPlugin::parseResponse(
	std::span<const std::byte> payload) noexcept
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
	auto versionEnd = std::ranges::find(payload, ' ');
	if (versionEnd == payload.end()) {
		return false;
	}

	auto statusBegin = std::next(versionEnd);
	if (statusBegin == payload.end()) {
		return false;
	}

	auto statusEnd = std::ranges::find(std::next(statusBegin), payload.end(), ' ');
	if (statusEnd == payload.end()) {
		return false;
	}

	/* Copy and check RTSP response code. */
	if (std::from_chars(
			statusBegin, statusEnd, m_exportData.code).ec == std::errc()) {
		return false;
	}

	if (m_responseParsed) {
		return FlowAction::FlushWithReinsert;
	}

	auto lineEnd = std::find(std::next(statusEnd), payload.end(), '\n');
	if (lineEnd == payload.end()) {
		return false;
	}

	RTSPExtensionReader reader(
		payload.subspan(std::next(lineEnd) - payload.data()));
	std::ranges::for_each(reader | 
		std::views::transform([](const Extension& extension) {
			if (extension.key == "Content-Type") {
				m_exportData.contentType.push_back(extension.value);
			}
			if (extension.key == "Server") {
				m_exportData.server.push_back(extension.value);
			}
		}));

	m_responseParsed = true;

	return true;
}

constexpr
FlowAction RTSPPlugin::updateExportData(
	std::span<const std::byte> payload) noexcept
{
	if (isRequest(payload)) {
		if (m_requestParsed) {
			return FlowAction::FlushWithReinsert;
		}
		if (!parseRequest(payload)) {
			return FlowAction::RequestNoData;
		}
	}

	if (isResponse(payload)) {
		if (m_responseParsed) {
			return FlowAction::FlushWithReinsert;
		}
		if (!parseResponse(payload)) {
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
