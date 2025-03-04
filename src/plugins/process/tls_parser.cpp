/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file tls_parser.cpp
 * \brief Class for parsing TLS traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \author Zainullin Damir <zaidamilda@gmail.com>
 * \date 2024
 */

#include "tls_parser.hpp"

#include <algorithm>
#include <functional>

#include <endian.h>

namespace ipxp {
uint64_t quic_get_variable_length(const uint8_t* start, uint64_t& offset)
{
	// find out length of parameter field (and load parameter, then move offset) , defined in:
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-summary-of-integer-encoding
	// this approach is used also in length field , and other QUIC defined fields.
	uint64_t tmp = 0;

	uint8_t two_bits = *(start + offset) & 0xC0;

	switch (two_bits) {
	case 0:
		tmp = *(start + offset) & 0x3F;
		offset += sizeof(uint8_t);
		return tmp;

	case 64:
		tmp = be16toh(*reinterpret_cast<const uint16_t*>(start + offset)) & 0x3FFF;
		offset += sizeof(uint16_t);
		return tmp;

	case 128:
		tmp = be32toh(*reinterpret_cast<const uint32_t*>(start + offset)) & 0x3FFFFFFF;
		offset += sizeof(uint32_t);
		return tmp;

	case 192:
		tmp = be64toh(*reinterpret_cast<const uint64_t*>(start + offset)) & 0x3FFFFFFFFFFFFFFF;
		offset += sizeof(uint64_t);
		return tmp;

	default:
		return 0;
	}
} // quic_get_variable_length

bool TLSParser::is_grease_value(uint16_t val)
{
	return val != 0 && !(val & ~(0xFAFA)) && ((0x00FF & val) == (val >> 8));
}

bool TLSParser::parse_tls(const uint8_t* packet, uint32_t length)
{
	return parse(packet, length, false);
}

bool TLSParser::parse_quic_tls(const uint8_t* packet, uint32_t length)
{
	return parse(packet, length, true);
}

bool TLSParser::parse(const uint8_t* packet, uint32_t length, bool is_quic)
{
	m_packet_data = packet;
	m_packet_length = length;
	clear_parsed_data();

	if (!parse_tls_header(is_quic)) {
		return false;
	}
	if (!parse_tls_handshake()) {
		return false;
	}

	if (m_handshake->type != TLS_HANDSHAKE_CLIENT_HELLO
		&& m_handshake->type != TLS_HANDSHAKE_SERVER_HELLO) {
		return false;
	}

	if (!parse_session_id()) {
		return false;
	}
	if (!parse_cipher_suites()) {
		return false;
	}
	if (!parse_compression_methods()) {
		return false;
	}
	return true;
}

bool TLSParser::parse_tls_header(bool is_quic) noexcept
{
	if (is_quic) {
		m_header_section_size = 0;
		return true;
	}
	const auto* tls_header = reinterpret_cast<const TLSHeader*>(m_packet_data);

	if (sizeof(TLSHeader) > m_packet_length) {
		return false;
	}
	if (tls_header == nullptr) {
		return false;
	}
	if (tls_header->type != TLS_HANDSHAKE) {
		return false;
	}
	if (tls_header->version.major != 3 || tls_header->version.minor > 3) {
		return false;
	}
	m_header_section_size = sizeof(TLSHeader);
	return true;
}

bool handshake_has_supported_version(const TLSHandshake* handshake)
{
	return handshake->version.major == 3 && handshake->version.minor >= 1
		&& handshake->version.minor <= 3;
}

bool handshake_has_supported_type(const TLSHandshake* handshake)
{
	return handshake->type == TLS_HANDSHAKE_CLIENT_HELLO
		|| handshake->type == TLS_HANDSHAKE_SERVER_HELLO;
}

bool TLSParser::parse_tls_handshake() noexcept
{
	const auto* handshake
		= reinterpret_cast<const TLSHandshake*>(m_packet_data + m_header_section_size);

	if (m_header_section_size + sizeof(TLSHandshake) > m_packet_length) {
		return false;
	}
	if (!handshake_has_supported_type(handshake)) {
		return false;
	}
	if (!handshake_has_supported_version(handshake)) {
		return false;
	}
	m_handshake = *handshake;
	return true;
}

bool TLSParser::parse_session_id() noexcept
{
	const size_t session_id_section_offset
		= m_header_section_size + sizeof(TLSHandshake) + TLS_RANDOM_BYTES_LENGTH;
	if (session_id_section_offset > m_packet_length) {
		return false;
	}

	const uint8_t sessionIdLength = *(m_packet_data + session_id_section_offset);
	m_session_id_section_length = sizeof(sessionIdLength) + sessionIdLength;
	if (session_id_section_offset + m_session_id_section_length > m_packet_length) {
		return false;
	}
	return true;
}

bool TLSParser::parse_cipher_suites() noexcept
{
	const size_t cipher_suite_section_offset = m_header_section_size + sizeof(TLSHandshake)
		+ TLS_RANDOM_BYTES_LENGTH + m_session_id_section_length;
	if (cipher_suite_section_offset + sizeof(uint16_t) > m_packet_length) {
		return false;
	}

	if (m_handshake->type == TLS_HANDSHAKE_SERVER_HELLO) {
		m_cipher_suites_section_length = sizeof(uint16_t);
		return true;
	}

	// Else parse Client Hello
	const uint16_t client_cipher_suites_length
		= ntohs(*reinterpret_cast<const uint16_t*>(m_packet_data + cipher_suite_section_offset));
	if (cipher_suite_section_offset + sizeof(client_cipher_suites_length)
			+ client_cipher_suites_length
		> m_packet_length) {
		return false;
	}

	const uint8_t* cipher_suites_begin
		= m_packet_data + cipher_suite_section_offset + sizeof(client_cipher_suites_length);
	const uint8_t* cipher_suites_end = cipher_suites_begin + client_cipher_suites_length;
	for (const uint8_t* cipher_suite = cipher_suites_begin; cipher_suite < cipher_suites_end;
		 cipher_suite += sizeof(uint16_t)) {
		const uint16_t type_id = ntohs(*reinterpret_cast<const uint16_t*>(cipher_suite));
		if (!is_grease_value(type_id)) {
			m_cipher_suits.push_back(type_id);
		}
	}
	m_cipher_suites_section_length
		= sizeof(client_cipher_suites_length) + client_cipher_suites_length;
	return true;
}

bool TLSParser::parse_compression_methods() noexcept
{
	const size_t compression_methods_section_offset = m_header_section_size + sizeof(TLSHandshake)
		+ TLS_RANDOM_BYTES_LENGTH + m_session_id_section_length + m_cipher_suites_section_length;
	if (compression_methods_section_offset > m_packet_length) {
		return false;
	}

	if (m_handshake->type == TLS_HANDSHAKE_SERVER_HELLO) {
		m_compression_methods_section_length = 1;
		return true;
	}
	// Else parse Client Hello
	const uint8_t compression_methods_length
		= *static_cast<const uint8_t*>(m_packet_data + compression_methods_section_offset);
	if (sizeof(compression_methods_length) + compression_methods_length > m_packet_length) {
		return false;
	}
	m_compression_methods_section_length
		= sizeof(compression_methods_length) + compression_methods_length;
	return true;
}

void TLSParser::parse_server_names(const uint8_t* extension_data, uint16_t extension_length)
{
	if (sizeof(uint16_t) > extension_length) {
		return;
	}
	const uint16_t servername_list_length
		= ntohs(*reinterpret_cast<const uint16_t*>(extension_data));
	if (sizeof(servername_list_length) + servername_list_length > extension_length) {
		return;
	}
	const uint8_t* sni_begin = extension_data + sizeof(servername_list_length);
	const uint8_t* sni_end = sni_begin + servername_list_length;

	for (const uint8_t* sni = sni_begin; sni + sizeof(TLSExtensionSNI) <= sni_end;) {
		const uint16_t sni_length = ntohs((reinterpret_cast<const TLSExtensionSNI*>(sni))->length);

		if (sni + sizeof(TLSExtensionSNI) + sni_length > extension_data + extension_length) {
			break;
		}
		m_server_names.emplace_back(
			reinterpret_cast<const char*>(sni) + sizeof(TLSExtensionSNI),
			sni_length);

		sni += sizeof(TLSExtensionSNI) + sni_length;
		m_objects_parsed++;
	}
}

void TLSParser::parse_elliptic_curves(
	const uint8_t* extension_payload,
	uint16_t extension_length) noexcept
{
	if (sizeof(uint16_t) > extension_length) {
		return;
	}
	const uint16_t supported_groups_length
		= ntohs(*reinterpret_cast<const uint16_t*>(extension_payload));
	if (sizeof(supported_groups_length) + supported_groups_length > extension_length) {
		return;
	}

	const uint8_t* supported_groups_begin = extension_payload + sizeof(supported_groups_length);
	const uint8_t* supported_groups_end = supported_groups_begin + supported_groups_length;

	for (const uint8_t* supported_group = supported_groups_begin;
		 supported_group < supported_groups_end;
		 supported_group += sizeof(uint16_t)) {
		const uint16_t supported_group_type
			= ntohs(*reinterpret_cast<const uint16_t*>(supported_group));
		if (!is_grease_value(supported_group_type)) {
			m_elliptic_curves.push_back(supported_group_type);
		}
	}
}

void TLSParser::parse_elliptic_curve_point_formats(
	const uint8_t* extension_payload,
	uint16_t extension_length) noexcept
{
	if (sizeof(uint8_t) > extension_length) {
		return;
	}
	const uint8_t supported_formats_length = *extension_payload;
	if (sizeof(supported_formats_length) + supported_formats_length > extension_length) {
		return;
	}

	const uint8_t* supportedFormatsBegin = extension_payload + sizeof(supported_formats_length);
	const uint8_t* supportedFormatsEnd = supportedFormatsBegin + supported_formats_length;
	std::string supportedFormats;

	for (const uint8_t* supported_format_pointer = supportedFormatsBegin;
		 supported_format_pointer < supportedFormatsEnd;
		 supported_format_pointer++) {
		const uint8_t supported_format = *supported_format_pointer;
		if (!is_grease_value(supported_format)) {
			m_elliptic_curve_point_formats.push_back(supported_format);
		}
	}
}

void TLSParser::parse_alpn(const uint8_t* extension_data, uint16_t extension_length)
{
	if (sizeof(uint16_t) > extension_length) {
		return;
	}
	const uint16_t alpnExtensionLength = ntohs(*reinterpret_cast<const uint16_t*>(extension_data));
	if (sizeof(uint16_t) + alpnExtensionLength > extension_length) {
		return;
	}

	const uint8_t* alpn_begin = extension_data + sizeof(uint16_t);
	const uint8_t* alpn_end = alpn_begin + alpnExtensionLength;

	for (const uint8_t* alpn = alpn_begin; alpn + sizeof(uint8_t) <= alpn_end;) {
		const uint8_t alpn_length = *alpn;

		if (alpn + sizeof(alpn_length) + alpn_length > alpn_begin + extension_length) {
			break;
		}
		m_alpns.emplace_back(
			reinterpret_cast<const char*>(alpn) + sizeof(alpn_length),
			alpn_length);
		alpn += sizeof(uint8_t) + alpn_length;
		m_objects_parsed++;
	}
}

void TLSParser::parse_signature_algorithms(
	const uint8_t* extension_data,
	uint16_t extension_length) noexcept
{
	const auto* signature_algorithm = reinterpret_cast<const uint16_t*>(extension_data);
	std::for_each_n(
		signature_algorithm,
		extension_length / sizeof(uint16_t),
		[this](uint16_t algorithm) { m_signature_algorithms.push_back(ntohs(algorithm)); });
}

void TLSParser::parse_supported_versions(
	const uint8_t* extension_data,
	uint16_t extension_length) noexcept
{
	if (m_handshake->type == TLS_HANDSHAKE_SERVER_HELLO) {
		if (sizeof(uint16_t) > extension_length) {
			return;
		}
		m_supported_versions.push_back(ntohs(*reinterpret_cast<const uint16_t*>(extension_data)));
		return;
	}
	// Else parse client hello
	if (sizeof(uint8_t) > extension_length) {
		return;
	}
	const uint8_t versions_length = *extension_data;
	if (sizeof(uint8_t) + versions_length > extension_length) {
		return;
	}

	const auto version
		= reinterpret_cast<const uint16_t*>(extension_data + sizeof(versions_length));
	std::for_each_n(version, versions_length / 2, [this](auto version) {
		if (!is_grease_value(version)) {
			m_supported_versions.push_back(ntohs(version));
		}
	});
}

bool TLSParser::parse_extensions(
	const std::function<void(uint16_t, const uint8_t*, uint16_t)>& callable) noexcept
{
	if (!has_valid_extension_length()) {
		return false;
	}
	const size_t extensions_section_offset = m_header_section_size + sizeof(TLSHandshake)
		+ TLS_RANDOM_BYTES_LENGTH + m_session_id_section_length + m_cipher_suites_section_length
		+ m_compression_methods_section_length;
	const uint16_t extensions_section_length
		= ntohs(*reinterpret_cast<const uint16_t*>(m_packet_data + extensions_section_offset));

	const uint8_t* extensions_begin
		= m_packet_data + extensions_section_offset + sizeof(extensions_section_length);
	const uint8_t* extensions_end = extensions_begin + extensions_section_length;

	for (const uint8_t* extension_ptr = extensions_begin; extension_ptr < extensions_end;) {
		const auto* extension = reinterpret_cast<const TLSExtension*>(extension_ptr);
		const uint16_t extension_length = ntohs(extension->length);
		const uint16_t extension_type = ntohs(extension->type);

		if (extension_ptr + sizeof(TLSExtension) + extension_length > extensions_end) {
			break;
		}

		const uint8_t* extensionPayload = extension_ptr + sizeof(TLSExtension);
		callable(extension_type, extensionPayload, extension_length);

		extension_ptr += sizeof(TLSExtension) + extension_length;
	}
	return true;
}

bool TLSParser::has_valid_extension_length() const noexcept
{
	const size_t extensions_section_offset = m_header_section_size + sizeof(TLSHandshake)
		+ TLS_RANDOM_BYTES_LENGTH + m_session_id_section_length + m_cipher_suites_section_length
		+ m_compression_methods_section_length;
	if (extensions_section_offset > m_packet_length) {
		return false;
	}
	const uint16_t extension_section_length
		= ntohs(*reinterpret_cast<const uint16_t*>(m_packet_data + extensions_section_offset));
	if (extensions_section_offset + extension_section_length > m_packet_length) {
		return false;
	}
	return true;
}

const std::optional<TLSHandshake>& TLSParser::get_handshake() const noexcept
{
	return m_handshake;
}

bool TLSParser::is_client_hello() const noexcept
{
	return m_handshake->type == TLS_HANDSHAKE_CLIENT_HELLO;
}

bool TLSParser::is_server_hello() const noexcept
{
	return m_handshake->type == TLS_HANDSHAKE_SERVER_HELLO;
}

const std::vector<TLSExtension>& TLSParser::get_extensions() const noexcept
{
	return m_extensions;
}

const std::vector<uint16_t>& TLSParser::get_cipher_suits() const noexcept
{
	return m_cipher_suits;
}

const std::vector<uint16_t>& TLSParser::get_elliptic_curves() const noexcept
{
	return m_elliptic_curves;
}

const std::vector<uint16_t>& TLSParser::get_elliptic_curve_point_formats() const noexcept
{
	return m_elliptic_curve_point_formats;
}

const std::vector<std::string_view>& TLSParser::get_alpns() const noexcept
{
	return m_alpns;
}

const std::vector<std::string_view>& TLSParser::get_server_names() const noexcept
{
	return m_server_names;
}

const std::vector<uint16_t>& TLSParser::get_supported_versions() const noexcept
{
	return m_supported_versions;
}

const std::vector<uint16_t>& TLSParser::get_signature_algorithms() const noexcept
{
	return m_signature_algorithms;
}

static void save_to_buffer(
	char* destination,
	const std::vector<std::string_view>& source,
	uint32_t size,
	char delimiter) noexcept
{
	std::for_each(
		source.begin(),
		source.end(),
		[destination, write_pos = 0UL, size, delimiter](const std::string_view& alpn) mutable {
			if (alpn.length() + 2U > size - write_pos) {
				destination[write_pos] = 0;
				return;
			}
			const size_t bytes_to_write = std::min(size - write_pos - 2U, alpn.length() + 2UL);
			memcpy(destination + write_pos, alpn.data(), bytes_to_write);
			write_pos += alpn.length();
			destination[write_pos++] = delimiter;
		});
}

void TLSParser::save_server_names(char* destination, uint32_t size) const noexcept
{
	save_to_buffer(destination, m_server_names, size, 0);
}

void TLSParser::save_alpns(char* destination, uint32_t size) const noexcept
{
	save_to_buffer(destination, m_alpns, size, 0);
}

void TLSParser::save_quic_user_agent(char* destination, uint32_t size) const noexcept
{
	save_to_buffer(destination, m_quic_user_agents, size, 0);
}

void TLSParser::parse_quic_user_agent(
	const uint8_t* extension_payload,
	uint16_t extension_length) noexcept
{
	const uint8_t* quic_transport_parameters_begin = extension_payload;
	const uint8_t* quic_transport_parameters_end
		= quic_transport_parameters_begin + extension_length;
	for (const uint8_t* parameter = quic_transport_parameters_begin;
		 parameter < quic_transport_parameters_end;) {
		size_t offset = 0UL;
		const size_t parameter_id = quic_get_variable_length(parameter, offset);
		const size_t parameter_length = quic_get_variable_length(parameter, offset);
		if (parameter + offset + parameter_length > quic_transport_parameters_end) {
			return;
		}
		if (parameter_id == TLS_EXT_GOOGLE_USER_AGENT) {
			m_objects_parsed++;
			m_quic_user_agents.emplace_back(
				reinterpret_cast<const char*>(parameter + offset),
				parameter_length);
		}
		parameter += offset + parameter_length;
	}
}

void TLSParser::clear_parsed_data() noexcept
{
	m_extensions.clear();
	m_cipher_suits.clear();
	m_signature_algorithms.clear();
	m_elliptic_curves.clear();
	m_elliptic_curve_point_formats.clear();
	m_alpns.clear();
	m_supported_versions.clear();
	m_server_names.clear();
}

void TLSParser::add_extension(uint16_t extension_type, uint16_t extension_length) noexcept
{
	m_extensions.emplace_back(TLSExtension {extension_type, extension_length});
}

} // namespace ipxp
