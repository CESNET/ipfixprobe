/**
 * @file
 * @brief Plugin for enriching flows for tls data.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * Provides a plugin that parses TLS traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */
#include "tls.hpp"

#include "ja3.hpp"
#include "ja4.hpp"
#include "tlsGetters.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <functional>
#include <iostream>
#include <numeric>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringUtils.hpp>

namespace ipxp::process::tls {

static const PluginManifest tlsPluginManifest = {
	.name = "tls",
	.description = "Tls process plugin for parsing tls traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("tls", "Parse TLS traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createTLSSchema(FieldManager& fieldManager, FieldHandlers<TLSFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("tls");

	handlers.insert(TLSFields::TLS_SNI, schema.addScalarField("TLS_SNI", getTLSSNIField));
	// handlers.insert(TLSFields::TLS_JA3, schema.addVectorField("TLS_JA3", getTLSJA3Field));
	handlers.insert(TLSFields::TLS_JA4, schema.addScalarField("TLS_JA4", getTLSJA4Field));
	handlers.insert(TLSFields::TLS_ALPN, schema.addScalarField("TLS_ALPN", getTLSALPNField));
	handlers.insert(
		TLSFields::TLS_VERSION,
		schema.addScalarField("TLS_VERSION", getTLSVersionField));
	/*handlers.insert(
		TLSFields::TLS_EXT_TYPE,
		schema.addVectorField("TLS_EXT_TYPE", getTLSExtensionTypesField));
	handlers.insert(
		TLSFields::TLS_EXT_LEN,
		schema.addVectorField("TLS_EXT_LEN", getTLSExtensionLengthsField));*/

	return schema;
}

TLSPlugin::TLSPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createTLSSchema(manager, m_fieldHandlers);
}

OnInitResult TLSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto payload = getPayload(*flowContext.packetContext.packet);
	TLSParser parser;
	if (!parser.parseHello(payload)) {
		return OnInitResult::Irrelevant;
	}

	auto& tlsContext = *std::construct_at(reinterpret_cast<TLSContext*>(pluginContext));
	parseTLS(
		payload,
		flowContext.flowRecord.flowKey.l4Protocol,
		tlsContext,
		flowContext.flowRecord);

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult TLSPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& tlsContext = *reinterpret_cast<TLSContext*>(pluginContext);
	if (!tlsContext.processingState.serverHelloParsed) {
		parseTLS(
			getPayload(*flowContext.packetContext.packet),
			flowContext.flowRecord.flowKey.l4Protocol,
			tlsContext,
			flowContext.flowRecord);
	}

	if (tlsContext.processingState.serverHelloParsed
		&& tlsContext.processingState.clientHelloParsed) {
		return OnUpdateResult::Final;
	}

	return OnUpdateResult::NeedsUpdate;
}

bool TLSPlugin::parseClientHelloExtensions(
	TLSParser& parser,
	TLSContext& tlsContext,
	FlowRecord& flowRecord) noexcept
{
	return parser.parseExtensions([&](const TLSExtension& extension) {
		switch (extension.type) {
		case TLSExtensionType::SERVER_NAME: {
			tlsContext.processingState.serverNames = parser.parseServerNames(extension.payload);
			if (!tlsContext.processingState.serverNames.has_value()) {
				return false;
			}
			concatenateRangeTo(*tlsContext.processingState.serverNames, tlsContext.serverNames, 0);
			m_fieldHandlers[TLSFields::TLS_SNI].setAsAvailable(flowRecord);
			break;
		}
		case TLSExtensionType::SUPPORTED_GROUPS: {
			tlsContext.processingState.supportedGroups
				= parser.parseSupportedGroups(extension.payload);
			if (!tlsContext.processingState.supportedGroups.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::ELLIPTIC_CURVE_POINT_FORMATS: {
			tlsContext.processingState.pointFormats
				= parser.parseEllipticCurvePointFormats(extension.payload);
			if (!tlsContext.processingState.pointFormats.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::ALPN: {
			tlsContext.processingState.alpns = parser.parseALPN(extension.payload);
			if (!tlsContext.processingState.alpns.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::SIGNATURE_ALGORITHMS: {
			tlsContext.processingState.signatureAlgorithms
				= parser.parseSignatureAlgorithms(extension.payload);
			if (!tlsContext.processingState.signatureAlgorithms.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::SUPPORTED_VERSION: {
			tlsContext.processingState.supportedVersions
				= parser.parseSupportedVersions(extension.payload, *parser.handshake);
			if (!tlsContext.processingState.supportedVersions.has_value()) {
				return false;
			}
			break;
		}
		default:
			break;
		}

		if (tlsContext.extensionTypes.size() != tlsContext.extensionTypes.capacity()) {
			tlsContext.extensionTypes.push_back(static_cast<uint16_t>(extension.type));
			m_fieldHandlers[TLSFields::TLS_EXT_TYPE].setAsAvailable(flowRecord);

			tlsContext.extensionLengths.push_back(extension.payload.size());
			m_fieldHandlers[TLSFields::TLS_EXT_LEN].setAsAvailable(flowRecord);
		}

		return true;
	});
}

bool TLSPlugin::parseServerHelloExtensions(
	TLSParser& parser,
	TLSContext& tlsContext,
	FlowRecord& flowRecord) noexcept
{
	return parser.parseExtensions([&](const TLSExtension& extension) {
		if (extension.type == TLSExtensionType::ALPN) {
			const std::optional<TLSParser::ALPNs> alpns = parser.parseALPN(extension.payload);
			if (!alpns.has_value()) {
				return false;
			}
			concatenateRangeTo(*alpns, tlsContext.serverALPNs, 0);
			m_fieldHandlers[TLSFields::TLS_ALPN].setAsAvailable(flowRecord);
		}

		if (extension.type == TLSExtensionType::SUPPORTED_VERSION) {
			tlsContext.processingState.supportedVersions
				= parser.parseSupportedVersions(extension.payload, *parser.handshake);
			if (!tlsContext.processingState.supportedVersions.has_value()) {
				return false;
			}
		}

		return true;
	});
}

void TLSPlugin::saveJA3(
	const TLSParser& parser,
	TLSContext& tlsContext,
	FlowRecord& flowRecord) noexcept
{
	if (!parser.cipherSuites.has_value() || !tlsContext.processingState.supportedGroups.has_value()
		|| !tlsContext.processingState.pointFormats.has_value()) {
		return;
	}

	JA3 ja3(
		std::bit_cast<uint16_t>(parser.handshake->version),
		toSpan<const uint16_t>(*parser.cipherSuites),
		toSpan<const uint16_t>(tlsContext.extensionTypes),
		toSpan<const uint16_t>(*tlsContext.processingState.supportedGroups),
		toSpan<const uint8_t>(*tlsContext.processingState.pointFormats));

	std::ranges::copy(ja3.getHash(), tlsContext.ja3.begin());
	m_fieldHandlers[TLSFields::TLS_JA3].setAsAvailable(flowRecord);
}

void TLSPlugin::saveJA4(
	const TLSParser& parser,
	const uint8_t l4Protocol,
	TLSContext& tlsContext,
	FlowRecord& flowRecord) noexcept
{
	if (!tlsContext.processingState.alpns.has_value()
		|| !tlsContext.processingState.signatureAlgorithms.has_value()
		|| !parser.cipherSuites.has_value() || !tlsContext.processingState.serverNames.has_value()
		|| !tlsContext.processingState.supportedVersions.has_value()) {
		return;
	}

	JA4 ja4(
		l4Protocol,
		*parser.handshake,
		toSpan<const std::string_view>(*tlsContext.processingState.serverNames),
		toSpan<const std::string_view>(*tlsContext.processingState.alpns),
		toSpan<const uint16_t>(*parser.cipherSuites),
		toSpan<const uint16_t>(tlsContext.extensionTypes),
		toSpan<const uint16_t>(*tlsContext.processingState.signatureAlgorithms),
		toSpan<const uint16_t>(*tlsContext.processingState.supportedVersions));

	std::ranges::copy(ja4.getView(), tlsContext.ja4.begin());
	m_fieldHandlers[TLSFields::TLS_JA4].setAsAvailable(flowRecord);
}

bool TLSPlugin::parseTLS(
	std::span<const std::byte> payload,
	const uint8_t l4Protocol,
	TLSContext& tlsContext,
	FlowRecord& flowRecord) noexcept
{
	TLSParser parser;
	if (!parser.parseHello(payload)) {
		return false;
	}

	if (parser.isClientHello()) {
		if (tlsContext.processingState.clientHelloParsed) {
			return true;
		}

		if (!parseClientHelloExtensions(parser, tlsContext, flowRecord)) {
			return false;
		}

		tlsContext.version = std::bit_cast<uint16_t>(parser.handshake->version);
		m_fieldHandlers[TLSFields::TLS_VERSION].setAsAvailable(flowRecord);
		saveJA3(parser, tlsContext, flowRecord);
		saveJA4(parser, l4Protocol, tlsContext, flowRecord);

		tlsContext.processingState.clientHelloParsed = true;

		return true;
	}

	if (parser.isServerHello()) {
		if (!parseServerHelloExtensions(parser, tlsContext, flowRecord)) {
			return false;
		}

		if (!tlsContext.processingState.supportedVersions.has_value()) {
			return false;
		}

		if (!tlsContext.processingState.supportedVersions->empty()) {
			tlsContext.version = tlsContext.processingState.supportedVersions->front();
		}

		tlsContext.processingState.serverHelloParsed = true;
	}

	return false;
}

void TLSPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<TLSContext*>(pluginContext));
}

PluginDataMemoryLayout TLSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(TLSContext),
		.alignment = alignof(TLSContext),
	};
}

static const PluginRegistrar<
	TLSPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	tlsRegistrar(tlsPluginManifest);

} // namespace ipxp::process::tls
