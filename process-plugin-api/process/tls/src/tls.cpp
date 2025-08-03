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

#include "md5.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <cctype>
#include <functional>
#include <iostream>
#include <numeric>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <stdio.h>

namespace ipxp {

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

// Print debug message if debugging is allowed.
#ifdef DEBUG_TLS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_TLS
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

TLSPlugin::TLSPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

OptionsParser* TLSPlugin::get_parser() const
{
	return new OptionsParser("tls", "Parse SNI from TLS traffic");
}

std::string TLSPlugin::get_name() const
{
	return "tls";
}

RecordExtTLS* TLSPlugin::get_ext() const
{
	return new RecordExtTLS(m_pluginID);
}

TLSPlugin::~TLSPlugin()
{
	close();
}

void TLSPlugin::init(const char* params)
{
	(void) params;
}

void TLSPlugin::close()
{
	if (ext_ptr != nullptr) {
		delete ext_ptr;
		ext_ptr = nullptr;
	}
}

ProcessPlugin* TLSPlugin::copy()
{
	return new TLSPlugin(*this);
}

int TLSPlugin::post_create(Flow& rec, const Packet& pkt)
{
	add_tls_record(rec, pkt);
	return 0;
}

int TLSPlugin::pre_update(Flow& rec, Packet& pkt)
{
	auto* ext = static_cast<RecordExtTLS*>(rec.get_extension(m_pluginID));

	if (ext != nullptr) {
		if (!ext->server_hello_parsed) {
			// Add ALPN from server packet
			parse_tls(pkt.payload, pkt.payload_len, ext, rec.ip_proto);
		}
		return 0;
	}
	add_tls_record(rec, pkt);

	return 0;
}


static std::string concatenate_vector_to_hex_string(const std::vector<uint16_t>& vector)
{
	if (vector.empty()) {
		return "";
	}
	auto res = std::accumulate(
		vector.begin(),
		vector.end(),
		std::string {},
		[](const std::string& acc, uint16_t value) {
			std::array<char, 6> buffer = {};
			std::snprintf(buffer.data(), buffer.size(), "%04x,", value);
			return acc + buffer.data();
		});
	res.pop_back();
	return res;
}


static const char* convert_version_to_label(uint16_t version)
{
	switch (version) {
	case 0x0304:
		return "13";
	case 0x0303:
		return "12";
	case 0x0302:
		return "11";
	case 0x0301:
		return "10";
	case 0x0300:
		return "s3";
	case 0x0002:
		return "s2";
	case 0xfeff:
		return "d1";
	case 0xfefd:
		return "d2";
	case 0xfefc:
		return "d3";
	default:
		return "00";
	}
}



static char convert_alpn_byte_to_label(char alpn_byte, bool high_nibble)
{
	if (std::isalnum(alpn_byte)) {
		return alpn_byte;
	} else {
		uint8_t nibble = high_nibble ? alpn_byte >> 4 : alpn_byte & 0x0F;
		return nibble < 0xA ? (char) ('0' + nibble) : (char) ('A' + nibble - 0xA);
	}
}

static const char* get_version_label(const TLSParser& parser)
{
	uint16_t version;
	if (parser.get_supported_versions().empty()) {
		version = parser.get_handshake()->version.version;
	} else {
		const auto* versions = (const int16_t*) parser.get_supported_versions().data();
		version = *std::max_element(versions, versions + parser.get_supported_versions().size());
	}
	return convert_version_to_label(version);
}

static std::string get_truncated_hash_hex(const std::string& str)
{
	std::array<char, 32> hash {};
	sha256::hash_it((const uint8_t*) str.c_str(), str.length(), (uint8_t*) hash.data());
	std::ostringstream oss;
	for (auto i = 0U; i < 6; ++i) {
		oss << std::hex << std::setw(2) << std::setfill('0') << ((uint16_t) hash[i] & 0xFF);
	}
	return oss.str();
}

static std::string get_truncated_cipher_hash(const TLSParser& parser)
{
	std::string cipher_string;
	std::vector<uint16_t> cipher_suits = parser.get_cipher_suits();
	std::sort(cipher_suits.begin(), cipher_suits.end());

	if (cipher_suits.empty()) {
		cipher_string.assign(12, '0');
		return cipher_string;
	}
	cipher_string = concatenate_vector_to_hex_string(cipher_suits);
	return get_truncated_hash_hex(cipher_string);
}

static std::string get_truncated_extensions_hash(const TLSParser& parser)
{
	std::vector<uint16_t> extensions;
	std::transform(
		parser.get_extensions().begin(),
		parser.get_extensions().end(),
		std::back_inserter(extensions),
		[](const TLSExtension& extension) { return extension.type; });
	extensions.erase(
		std::remove_if(
			extensions.begin(),
			extensions.end(),
			[](uint16_t extension_type) {
				return extension_type == TLS_EXT_ALPN || extension_type == TLS_EXT_SERVER_NAME
					|| TLSParser::is_grease_value(extension_type);
			}),
		extensions.end());
	std::sort(extensions.begin(), extensions.end());

	auto extensions_string = concatenate_vector_to_hex_string(extensions);
	std::vector<uint16_t> signature_algorithms = parser.get_signature_algorithms();
	if (!signature_algorithms.empty()) {
		signature_algorithms.erase(signature_algorithms.begin());
	}
	auto signature_algorithms_string = concatenate_vector_to_hex_string(signature_algorithms);

	auto extensions_and_algorithms_string = extensions_string + '_' + signature_algorithms_string;
	return get_truncated_hash_hex(extensions_and_algorithms_string);
}

static std::string get_alpn_label(const TLSParser& parser)
{
	std::string alpn_label;
	if (parser.get_alpns().empty() || parser.get_alpns()[0].empty()) {
		alpn_label = "00";
	} else {
		const auto& alpn_string = parser.get_alpns()[0];
		alpn_label += convert_alpn_byte_to_label(alpn_string[0], true);
		alpn_label += convert_alpn_byte_to_label(alpn_string[alpn_string.length() - 1], false);
	}
	return alpn_label;
}

static std::string get_ja4_string(const TLSParser& parser, uint8_t ip_proto)
{
	constexpr const uint8_t UDP_ID = 17;
	const char protocol = ip_proto == UDP_ID ? 'q' : 't';

	char version_label[3];
	*(uint16_t*) version_label = *(uint16_t*) get_version_label(parser);
	version_label[2] = 0;

	const char sni_label = parser.get_server_names().empty() ? 'i' : 'd';

	const uint8_t ciphers_count = std::min(parser.get_cipher_suits().size(), 99UL);

	const uint8_t extension_count = std::min(parser.get_extensions().size(), 99UL);

	const auto alpn_label = get_alpn_label(parser);

	const auto truncated_cipher_hash = get_truncated_cipher_hash(parser);

	const auto truncated_extensions_hash = get_truncated_extensions_hash(parser);

	return std::string {} + protocol + version_label + sni_label + std::to_string(ciphers_count)
		+ std::to_string(extension_count) + alpn_label + '_' + truncated_cipher_hash + '_'
		+ truncated_extensions_hash;
}



constexpr 
bool TLSParser::parseClientHelloExtensions(TLSParser& parser) noexcept
{
	return parser.parse_extensions([&parser](const Extension& extension) {
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
void TLSPlugin::saveJA4(const uint8_t l4Protocol) noexcept
{
	JA4 ja4(parser.get_handshake()->version.version,
		toSpan(parser.get_cipher_suits()),
		toSpan(m_exportData.extensionTypes),
		toSpan(m_exportData.extensionLengths),
		toSpan(m_supportedGroups),
		toSpan(m_pointFormats)
	);

	std::ranges::copy(ja3.getHash(), m_exportData.ja3.begin());
}


bool TLSPlugin::parse_tls(
	const uint8_t* data,
	uint16_t payload_len,
	RecordExtTLS* rec,
	uint8_t ip_proto)
{
	TLSParser parser;
	if (!parser.parse_tls(data, payload_len)) {
		return false;
	}

	if (parser.is_client_hello()) {
		if (m_clientHelloParsed) {
			return true;
		}
		if (!parseClientHelloExtensions(parser)) {
			return false;
		}

		rec->version = parser.get_handshake()->version.version;
		//parser.save_server_names(rec->sni, sizeof(rec->sni));
		saveJA3();
		auto ja4 = get_ja4_string(parser, ip_proto);
		std::memcpy(rec->ja4, ja4.c_str(), ja4.length());
		return true;
	} else if (parser.is_server_hello()) {
		if (!parse_server_hello_extensions(parser)) {
			return false;
		}
		rec->server_hello_parsed = true;
		parser.save_alpns(rec->alpn, sizeof(rec->alpn));
		rec->version = parser.get_supported_versions().empty() ? rec->version
															   : parser.get_supported_versions()[0];
	}
	return false;
}

void TLSPlugin::add_tls_record(Flow& rec, const Packet& pkt)
{
	if (ext_ptr == nullptr) {
		ext_ptr = new RecordExtTLS(m_pluginID);
	}

	if (parse_tls(pkt.payload, pkt.payload_len, ext_ptr, rec.ip_proto)) {
		DEBUG_CODE(for (int i = 0; i < 16; i++) { DEBUG_MSG("%02x", ext_ptr->ja3[i]); })
		DEBUG_MSG("\n");
		DEBUG_MSG("%s\n", ext_ptr->sni);
		DEBUG_MSG("%s\n", ext_ptr->alpn);
		rec.add_extension(ext_ptr);
		ext_ptr = nullptr;
	}
}

void TLSPlugin::finish(bool print_stats)
{
	if (print_stats) {
		std::cout << "TLS plugin stats:" << std::endl;
		std::cout << "   Parsed SNI: " << parsed_sni << std::endl;
	}
}

static const PluginRegistrar<TLSPlugin, ProcessPluginFactory> tlsRegistrar(tlsPluginManifest);

} // namespace ipxp
