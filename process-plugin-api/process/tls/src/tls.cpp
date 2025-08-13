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

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

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

const inline std::vector<FieldPair<TLSFields>> fields = {
	{TLSFields::TLS_SNI, "TLS_SNI"},
	{TLSFields::TLS_JA3, "TLS_JA3"},
	{TLSFields::TLS_JA4, "TLS_JA4"},
	{TLSFields::TLS_ALPN, "TLS_ALPN"},
	{TLSFields::TLS_VERSION, "TLS_VERSION"},
	{TLSFields::TLS_EXT_TYPE, "TLS_EXT_TYPE"},
	{TLSFields::TLS_EXT_LEN, "TLS_EXT_LEN"},
};


static FieldSchema createTLSSchema()
{
	FieldSchema schema("tls");

	// TODO EXPORT STRINGS

	schema.addVectorField<uint8_t>(
		"TLS_JA3",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const uint8_t> {
			return getSpan(reinterpret_cast<const TLSExport*>(thisPtr)
				->ja3);
		});

	schema.addScalarField<uint16_t>(
		"TLS_VERSION",
		FieldDirection::DirectionalIndifferent,
		offsetof(TLSExport, version));

	schema.addVectorField<int16_t>(
		"TLS_EXT_TYPE",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const int16_t> {
			return getSpan(reinterpret_cast<const TLSExport*>(thisPtr)
				->extensionTypes);
		});

	schema.addVectorField<int16_t>(
		"TLS_EXT_LEN",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const int16_t> {
			return getSpan(reinterpret_cast<const TLSExport*>(thisPtr)
				->extensionLengths);
		});

	return schema;
}

TLSPlugin::TLSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createTLSSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction TLSPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	parseTLS(packet);

	return FlowAction::RequestFullData;
}

FlowAction TLSPlugin::onFlowUpdate(FlowRecord& flowRecord, 
	const Packet& packet)
{
	if (!m_serverHelloParsed) {
		parseTLS(packet);
	}

	if (m_serverHelloParsed && m_clientHelloParsed) {
		makeAllFieldsAvailable(flowRecord);
		return FlowAction::RequestNoData;
	}

	return FlowAction::RequestFullData;
}

constexpr 
bool TLSParser::parseClientHelloExtensions(TLSParser& parser) noexcept
{
	return parser.parseExtensions([&parser](const Extension& extension) {
		switch (extension.type)
		{
		case TLSExtensionType::SERVER_NAME:
			const std::optional<TLSParser::ServerNames> serverNames 
				= parser.parseServerNames(extension.payload);
			if (!serverNames.has_value()) {
				return false;
			}
			concatenateFromTo(*serverNames, m_exportData.serverNames, 0);
			break;
		case TLSExtensionType::SUPPORTED_GROUPS:
			m_supportedGroups = parser.parseSupportedGroups(extension.payload);
			if (!m_supportedGroups.has_value()) {
				return false;
			}
			break;
		case TLSExtensionType::ELLIPTIC_CURVE_POINT_FORMATS:
			m_pointFormats = parser.parseEllipticCurvePointFormats(extension.payload);
			if (!m_pointFormats.has_value()) {
				return false;
			}
			break;
		case TLSExtensionType::ALPN:
			m_alpns = parser.parseALPN(extension.payload);
			if (!m_alpns.has_value()) {
				return false;
			}
			break;
		case TLSExtensionType::SIGNATURE_ALGORITHMS:
			m_signatureAlgorithms 
				= parser.parseSignatureAlgorithms(extension.payload);
			if (!m_signatureAlgorithms.has_value()) {
				return false;
			}
			break;
		case TLSExtensionType::SUPPORTED_VERSION:
			m_supportedVersions 
				= parser.parseSupportedVersions(extension.payload);
			if (!m_supportedVersions.has_value()) {
				return false;
			}
			break;
		default:
			break;
		}

		if (!m_exportData.extensionTypes.full()) {
			m_exportData.extensionTypes.push_back(extension.type);
			m_exportData.extensionLengths.push_back(extension.payload.size());
		}

		return true;
	});
}

constexpr
bool TLSParser::parseServerHelloExtensions(TLSParser& parser) noexcept
{
	return parser.parseExtensions([&parser](const Extension& extension) {
		if (extension.type == TLSExtensionType::ALPN) {
			const std::optional<ALPNs> alpns 
				= parser.parseALPN(extension.payload);
			if (!alpns.has_value()) {
				return false;
			}
			concatenateFromTo(*alpns, m_exportData.serverALPNs, 0);
		}
		if (extension.type == TLSExtensionType::SUPPORTED_VERSION) {
			m_supportedVersions 
				= parser.parseSupportedVersions(extension.payload);
			if (!m_supportedVersions.has_value()) {
				return false;
			}
		}
		return true;
	});
}

constexpr
void TLSPlugin::saveJA3() noexcept
{
	JA3 ja3(parser.get_handshake()->version.version,
		toSpan(parser.get_cipher_suits()),
		toSpan(m_exportData.extensionTypes),
		toSpan(m_exportData.extensionLengths),
		toSpan(m_supportedGroups),
		toSpan(m_pointFormats)
	);

	std::ranges::copy(ja3.getHash(), m_exportData.ja3.begin());
}

constexpr
bool TLSPlugin::saveJA4(const uint8_t l4Protocol) noexcept
{
	if (!m_alpns.has_value() || !m_signatureAlgorithms.has_value()) {
		return false;
	}

	JA4 ja4(parser.get_handshake(),
		toSpan(parser.getServerNames()),
		toSpan(*m_alpns),
		toSpan(parser.getCipherSuites()),
		toSpan(m_exportData.extensionTypes),
		toSpan(*m_signatureAlgorithms)
	);

	std::ranges::copy(ja4.getView(), m_exportData.ja4.begin());
}

constexpr
bool TLSPlugin::parseTLS(
	std::span<const std::byte> payload, const uint8_t l4Protocol) noexcept
{
	TLSParser parser;
	if (!parser.parseHello(payload)) {
		return false;
	}

	if (parser.isClienthello()) {
		if (m_clientHelloParsed) {
			return true;
		}

		if (!parseClientHelloExtensions(parser)) {
			return false;
		}

		m_exportData.version = *reinterpret_cast<const uint16_t*>(
			parser.getHandshake()->version);
		saveJA3();
		saveJA4();

		m_clientHelloParsed = true;

		return true;
	}

	if (parser.isServerHello()) {
		if (!parseServerHelloExtensions(parser)) {
			return false;
		}

		if (!m_supportedVersions.has_value()) {
			return false;
		}

		if (!m_supportedVersions->empty()) {
			m_exportData.version = m_supportedVersions->front();
		}
	
		m_serverHelloParsed = true;
	}

	return false;
}

ProcessPlugin* TLSPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<TLSPlugin*>(constructAtAddress), *this);
}

std::string TLSPlugin::getName() const { 
	return tlsPluginManifest.name; 
}

const void* TLSPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<TLSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> 
	tlsRegistrar(tlsPluginManifest);

} // namespace ipxp
