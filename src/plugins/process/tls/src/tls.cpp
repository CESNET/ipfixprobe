/**
 * @file
 * @brief Plugin for enriching flows for tls data.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tls.hpp"

#include <algorithm>
#include <cctype>
#include <functional>
#include <iostream>
#include <numeric>
#include <bit>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <utils/stringUtils.hpp>
#include <utils/spanUtils.hpp>

#include "ja3.hpp"
#include "ja4.hpp"

namespace ipxp {

static const PluginManifest tlsPluginManifest = {
	.name = "tls",
	.description = "Tls process plugin for parsing tls traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("tls", "Parse TLS traffic");
			parser.usage(std::cout);*/
		},
};

static FieldSchema createTLSSchema(FieldManager& fieldManager, FieldHandlers<TLSFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("tls");

	handlers.insert(TLSFields::TLS_SNI, schema.addScalarField(
		"TLS_SNI",
		[](const void* context) { return toStringView(reinterpret_cast<const TLSData*>(context)->serverNames); }
	));
	// TODO FIX
	/*handlers.insert(TLSFields::TLS_JA3, schema.addVectorField(
		"TLS_JA3",
		[](const void* context) { return toSpan<const uint8_t>(reinterpret_cast<const TLSData*>(context)->ja3); }
	));*/
	handlers.insert(TLSFields::TLS_JA4, schema.addScalarField(
		"TLS_JA4",
		[](const void* context) { return toStringView(reinterpret_cast<const TLSData*>(context)->ja4); }
	));
	handlers.insert(TLSFields::TLS_ALPN, schema.addScalarField(
		"TLS_ALPN",
		[](const void* context) { return toStringView(reinterpret_cast<const TLSData*>(context)->serverALPNs); }
	));
	handlers.insert(TLSFields::TLS_VERSION, schema.addScalarField(
		"TLS_VERSION",
		[](const void* context) { return reinterpret_cast<const TLSData*>(context)->version; }
	));
	/*handlers.insert(TLSFields::TLS_EXT_TYPE, schema.addVectorField(
		"TLS_EXT_TYPE",
		[](const void* context) { return toSpan<const uint16_t>(reinterpret_cast<const TLSData*>(context)->extensionTypes); }
	));
	handlers.insert(TLSFields::TLS_EXT_LEN, schema.addVectorField(
		"TLS_EXT_LEN",
		[](const void* context) { return toSpan<const uint16_t>(reinterpret_cast<const TLSData*>(context)->extensionLengths); }
	));*/

	return schema;
}

TLSPlugin::TLSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createTLSSchema(manager, m_fieldHandlers);
}

PluginInitResult TLSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<TLSData*>(pluginContext));
	parseTLS(toSpan<const std::byte>(
		flowContext.packet.payload, flowContext.packet.payload_len), flowContext.packet.ip_proto, *pluginData, flowContext.flowRecord);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	}; 
}

PluginUpdateResult TLSPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<TLSData*>(pluginContext);
	if (!pluginData->processingState.serverHelloParsed) {
		parseTLS(toSpan<const std::byte>(
			flowContext.packet.payload, flowContext.packet.payload_len), flowContext.packet.ip_proto, *pluginData, flowContext.flowRecord);
	}

	if (pluginData->processingState.serverHelloParsed && pluginData->processingState.clientHelloParsed) {
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

bool TLSPlugin::parseClientHelloExtensions(TLSParser& parser, TLSData& pluginData, FlowRecord& flowRecord) noexcept
{
	return parser.parseExtensions([&](const TLSExtension& extension) {
		switch (extension.type)
		{
		case TLSExtensionType::SERVER_NAME: {
			pluginData.processingState.serverNames = parser.parseServerNames(extension.payload);
			if (!pluginData.processingState.serverNames.has_value()) {
				return false;
			}
			concatenateRangeTo(*pluginData.processingState.serverNames, pluginData.serverNames, 0);
			m_fieldHandlers[TLSFields::TLS_SNI].setAsAvailable(flowRecord);
			break;
		}
		case TLSExtensionType::SUPPORTED_GROUPS: {
			pluginData.processingState.supportedGroups = parser.parseSupportedGroups(extension.payload);
			if (!pluginData.processingState.supportedGroups.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::ELLIPTIC_CURVE_POINT_FORMATS: {
			pluginData.processingState.pointFormats = parser.parseEllipticCurvePointFormats(extension.payload);
			if (!pluginData.processingState.pointFormats.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::ALPN: {
			pluginData.processingState.alpns = parser.parseALPN(extension.payload);
			if (!pluginData.processingState.alpns.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::SIGNATURE_ALGORITHMS: {
			pluginData.processingState.signatureAlgorithms 
				= parser.parseSignatureAlgorithms(extension.payload);
			if (!pluginData.processingState.signatureAlgorithms.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::SUPPORTED_VERSION: {
			pluginData.processingState.supportedVersions 
				= parser.parseSupportedVersions(extension.payload, *parser.handshake);
			if (!pluginData.processingState.supportedVersions.has_value()) {
				return false;
			}
			break;
		}
		default:
			break;
		}

		if (pluginData.extensionTypes.size() != pluginData.extensionTypes.capacity()) {
			pluginData.extensionTypes.push_back(static_cast<uint16_t>(extension.type));
			m_fieldHandlers[TLSFields::TLS_EXT_TYPE].setAsAvailable(flowRecord);
			
			pluginData.extensionLengths.push_back(extension.payload.size());
			m_fieldHandlers[TLSFields::TLS_EXT_LEN].setAsAvailable(flowRecord);
		}

		return true;
	});
}

bool TLSPlugin::parseServerHelloExtensions(TLSParser& parser, TLSData& pluginData, FlowRecord& flowRecord) noexcept
{
	return parser.parseExtensions([&](const TLSExtension& extension) {
		if (extension.type == TLSExtensionType::ALPN) {
			const std::optional<TLSParser::ALPNs> alpns 
				= parser.parseALPN(extension.payload);
			if (!alpns.has_value()) {
				return false;
			}
			concatenateRangeTo(*alpns, pluginData.serverALPNs, 0);
			m_fieldHandlers[TLSFields::TLS_ALPN].setAsAvailable(flowRecord);
		}
		
		if (extension.type == TLSExtensionType::SUPPORTED_VERSION) {
			pluginData.processingState.supportedVersions
				= parser.parseSupportedVersions(extension.payload, *parser.handshake);
			if (!pluginData.processingState.supportedVersions.has_value()) {
				return false;
			}
		}

		return true;
	});
}

void TLSPlugin::saveJA3(const TLSParser& parser, TLSData& pluginData, FlowRecord& flowRecord) noexcept
{
	if (!parser.cipherSuites.has_value()
		|| !pluginData.processingState.supportedGroups.has_value()
		|| !pluginData.processingState.pointFormats.has_value()) {
		return;
	}

	JA3 ja3(std::bit_cast<uint16_t>(parser.handshake->version),
		toSpan<const uint16_t>(*parser.cipherSuites),
		toSpan<const uint16_t>(pluginData.extensionTypes),
		toSpan<const uint16_t>(*pluginData.processingState.supportedGroups),
		toSpan<const uint8_t>(*pluginData.processingState.pointFormats)
	);

	std::ranges::copy(ja3.getHash(), pluginData.ja3.begin());
	m_fieldHandlers[TLSFields::TLS_JA3].setAsAvailable(flowRecord);
}

void TLSPlugin::saveJA4(const TLSParser& parser, const uint8_t l4Protocol, TLSData& pluginData, FlowRecord& flowRecord) noexcept
{
	if (!pluginData.processingState.alpns.has_value()
		|| !pluginData.processingState.signatureAlgorithms.has_value()
		|| !parser.cipherSuites.has_value()
		|| !pluginData.processingState.serverNames.has_value()
		|| !pluginData.processingState.supportedVersions.has_value()) {
		return;
	}

	JA4 ja4(l4Protocol,
		*parser.handshake,
		toSpan<const std::string_view>(*pluginData.processingState.serverNames),
		toSpan<const std::string_view>(*pluginData.processingState.alpns),
		toSpan<const uint16_t>(*parser.cipherSuites),
		toSpan<const uint16_t>(pluginData.extensionTypes),
		toSpan<const uint16_t>(*pluginData.processingState.signatureAlgorithms),
		toSpan<const uint16_t>(*pluginData.processingState.supportedVersions)
	);

	std::ranges::copy(ja4.getView(), pluginData.ja4.begin());
	m_fieldHandlers[TLSFields::TLS_JA4].setAsAvailable(flowRecord);
}

constexpr
bool TLSPlugin::parseTLS(
	std::span<const std::byte> payload, const uint8_t l4Protocol, TLSData& pluginData, FlowRecord& flowRecord) noexcept
{
	TLSParser parser;
	if (!parser.parseHello(payload)) {
		return false;
	}

	if (parser.isClientHello()) {
		if (pluginData.processingState.clientHelloParsed) {
			return true;
		}

		if (!parseClientHelloExtensions(parser, pluginData, flowRecord)) {
			return false;
		}

		pluginData.version = std::bit_cast<uint16_t>(parser.handshake->version);
		m_fieldHandlers[TLSFields::TLS_VERSION].setAsAvailable(flowRecord);
		saveJA3(parser, pluginData, flowRecord);
		saveJA4(parser, l4Protocol, pluginData, flowRecord);

		pluginData.processingState.clientHelloParsed = true;

		return true;
	}

	if (parser.isServerHello()) {
		if (!parseServerHelloExtensions(parser, pluginData, flowRecord)) {
			return false;
		}

		if (!pluginData.processingState.supportedVersions.has_value()) {
			return false;
		}

		if (!pluginData.processingState.supportedVersions->empty()) {
			pluginData.version = pluginData.processingState.supportedVersions->front();
		}

		pluginData.processingState.serverHelloParsed = true;
	}

	return false;
}

static const PluginRegistrar<TLSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> 
	tlsRegistrar(tlsPluginManifest);

} // namespace ipxp
