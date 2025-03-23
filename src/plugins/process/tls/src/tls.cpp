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
#include "md5.hpp"
#include "sha256.hpp"
#include "tls.hpp"

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
	.usage = nullptr,
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

static std::string concatenate_vector_to_string(const std::vector<uint16_t>& vector)
{
	if (vector.empty()) {
		return "";
	}
	return std::accumulate(
		std::next(vector.begin()),
		vector.end(),
		std::to_string(vector[0]),
		[](const std::string& a, uint16_t b) { return a + "-" + std::to_string(b); });
}

static std::string concatenate_vector_to_hex_string(const std::vector<uint16_t>& vector)
{
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

static std::string
concatenate_extensions_vector_to_string(const std::vector<TLSExtension>& extensions)
{
	auto res = std::accumulate(
		extensions.begin(),
		extensions.end(),
		std::string {},
		[](const std::string& a, const auto& extension) {
			if (TLSParser::is_grease_value(extension.type)) {
				return a;
			}
			return a + std::to_string(extension.type) + "-";
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

static std::string get_ja3_string(const TLSParser& parser)
{
	std::string ja3_string = std::to_string(parser.get_handshake()->version.version) + ',';
	ja3_string += concatenate_vector_to_string(parser.get_cipher_suits()) + ',';
	ja3_string += concatenate_extensions_vector_to_string(parser.get_extensions()) + ',';
	ja3_string += concatenate_vector_to_string(parser.get_elliptic_curves()) + ',';
	ja3_string += concatenate_vector_to_string(parser.get_elliptic_curve_point_formats());
	return ja3_string;
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

static bool parse_client_hello_extensions(TLSParser& parser) noexcept
{
	return parser.parse_extensions([&parser](
									   uint16_t extension_type,
									   const uint8_t* extension_payload,
									   uint16_t extension_length) {
		if (extension_type == TLS_EXT_SERVER_NAME) {
			parser.parse_server_names(extension_payload, extension_length);
		} else if (extension_type == TLS_EXT_ECLIPTIC_CURVES) {
			parser.parse_elliptic_curves(extension_payload, extension_length);
		} else if (extension_type == TLS_EXT_EC_POINT_FORMATS) {
			parser.parse_elliptic_curve_point_formats(extension_payload, extension_length);
		} else if (extension_type == TLS_EXT_ALPN) {
			parser.parse_alpn(extension_payload, extension_length);
		} else if (extension_type == TLS_EXT_SIGNATURE_ALGORITHMS) {
			parser.parse_signature_algorithms(extension_payload, extension_length);
		} else if (extension_type == TLS_EXT_SUPPORTED_VER) {
			parser.parse_supported_versions(extension_payload, extension_length);
		}
		parser.add_extension(extension_type, extension_length);
	});
}

static bool parse_server_hello_extensions(TLSParser& parser) noexcept
{
	return parser.parse_extensions([&parser](
									   uint16_t extension_type,
									   const uint8_t* extension_payload,
									   uint16_t extension_length) {
		if (extension_type == TLS_EXT_ALPN) {
			parser.parse_alpn(extension_payload, extension_length);
		} else if (extension_type == TLS_EXT_SUPPORTED_VER) {
			parser.parse_supported_versions(extension_payload, extension_length);
		}
	});
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
		if (!parse_client_hello_extensions(parser)) {
			return false;
		}
		if (rec->extensions_buffer_size == 0) {
			const auto count_to_copy
				= std::min(rec->extension_types.size(), parser.get_extensions().size());
			std::transform(
				parser.get_extensions().begin(),
				parser.get_extensions().begin() + count_to_copy,
				rec->extension_types.begin(),
				[](const auto& typeLength) { return typeLength.type; });
			std::transform(
				parser.get_extensions().begin(),
				parser.get_extensions().begin() + count_to_copy,
				rec->extension_lengths.begin(),
				[](const auto& typeLength) { return typeLength.length; });
			rec->extensions_buffer_size = count_to_copy;
		}
		rec->version = parser.get_handshake()->version.version;
		parser.save_server_names(rec->sni, sizeof(rec->sni));
		md5_get_bin(get_ja3_string(parser), rec->ja3);
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
