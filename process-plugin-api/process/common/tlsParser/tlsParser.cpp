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

#include "tlsParser.hpp"

#include <algorithm>
#include <functional>
#include <endian.h>

#include <utils/spanUtils.hpp>

#include "tlsCipherSuite.hpp"
#include "tlsHeader.hpp"
#include "tlsHandshakeHeader.hpp"
#include "tlsSNIReader.hpp"
#include "extensionReaders/extensionReader.hpp"


namespace ipxp {

constexpr static
bool isGreaseValue(const uint16_t val) noexcept
{
	return val != 0 && !(val & ~(0xFAFA)) && ((0x00FF & val) == (val >> 8));
}

bool TLSParser::parseHello(std::span<const std::byte> payload)
{
	return parse(payload, false);
}

bool TLSParser::parseHelloFromQUIC(std::span<const std::byte> payload)
{
	return parse(payload, true);
}

constexpr static
std::optional<uint8_t> 
getSessionIdSectionLength(std::span<const std::byte> payload) noexcept
{
	constexpr std::size_t MAX_SESSION_ID_LENGTH = 32;
	if (payload.empty()) {
		return std::nullopt;
	}

	const uint8_t sessionIdLength = static_cast<uint8_t>(payload[0]);
	if (payload.size() < sizeof(sessionIdLength) + sessionIdLength ||
		sessionIdLength > MAX_SESSION_ID_LENGTH) {
		return std::nullopt;
	}

	return sessionIdLength + sizeof(sessionIdLength);
}

constexpr static
std::optional<std::size_t>
getCompressionMethodsLength(std::span<const std::byte> payload,
	const TLSHandshakeHeader& handshake) noexcept
{
	if (payload.empty()) {
		return std::nullopt;
	}

	if (handshake.type == TLSHandshakeHeader::Type::SERVER_HELLO) {
		return sizeof(uint8_t);
	}

	// Else parse Client Hello
	const uint8_t compressionMethodsLength
		= *static_cast<const uint8_t*>(payload.data());
	if (sizeof(compressionMethodsLength) + compressionMethodsLength > payload.size()) {
		return std::nullopt;
	}

	return sizeof(compressionMethodsLength) + compressionMethodsLength;
}

constexpr static
std::optional<std::size_t> 
parseHeader(std::span<const std::byte> payload, const bool isQUIC) noexcept
{
	if (isQUIC) {
		m_header_section_size = 0;
		return 0;
	}
	const auto* tls_header = reinterpret_cast<const TLSHeader*>(payload.data());

	if (sizeof(TLSHeader) > payload.size()) {
		return std::nullopt;
	}

	if (tls_header->type != Header::Type::HANDSHAKE) {
		return std::nullopt;
	}

	if (tls_header->version.bytes.major != 3 || 
		tls_header->version.bytes.minor > 3) {
		return std::nullopt;
	}

	return sizeof(TLSHeader);
}

constexpr
bool TLSParser::parseExtensions(
	const std::function<bool(const Extension&)>& callable) noexcept
{
	ExtensionReader reader(*m_extension);
	return std::ranges::all_of(
		reader |
		std::views::transform(callable)
	);
}

constexpr static 
std::optional<std::span<const std::byte>>
getExtensionsSection(std::span<const std::byte> payload) noexcept
{
	if (payload.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

	const uint16_t extensionsLength 
		= ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
	if (payload.size() < extensionsLength + sizeof(extensionsLength)) {
		return std::nullopt;
	}

	return payload.subspan(sizeof(extensionsLength), extensionsLength);
}


bool TLSParser::parse(std::span<const std::byte> payload, const bool isQUIC)
{
	clear_parsed_data();

	const std::optional<std::size_t> headerLength 
		= isQUIC 
		? std::make_optional(0) 
		: parseHeader(payload);
	if (!headerLength) {
		return false;
	}

	const std::size_t handshakeOffset = *headerLength;
	m_handshake = parseHandshake(payload.subspan(handshakeOffset));
	if (!m_handshake) {
		return false;
	}

	constexpr std::size_t randomBytesLength = 32;
	const std::size_t sessionIdLengthOffset = handshakeOffset + randomBytesLength;
	const std::optional<uint8_t> sessionIdSectionLength
		= getSessionIdSectionLength(payload.subspan(sessionIdLengthOffset));
	if (!sessionIdSectionLength) {
		return false;
	}

	const std::size_t cipherSuitesOffset 
		= sessionIdLengthOffset + *sessionIdSectionLength;
	if (m_handshake.type == TLSHandshakeHeader::Type::CLIENT_HELLO) {
		m_cipherSuites = parseCipherSuites(payload.subspan(cipherSuitesOffset), &m_handshake);
		if (!m_cipherSuites.has_value()) {
			return false;
		}
	}

	const std::size_t compressionMethodsOffset = cipherSuitesOffset 
		+ sizeof(uint16_t) + (m_cipherSuites.has_value() 
		? m_cipherSuites->size() * sizeof(uint16_t) : 0);
	const std::optional<std::size_t> compressionMethodsLength
		= parseCompressionMethods(payload.subspan(compressionMethodsOffset), *handshake);
	if (!compressionMethodsLength.has_value()) {
		return false;
	}

	m_extensions = getExtensionsSection(
		payload.subspan(compressionMethodsOffset + *compressionMethodsLength));
	if (!m_extensions.has_value()) {
		return false;
	}

	return true;
}


bool handshakeHasSupportedVersion(const TLSHandshake& handshake)
{
	return handshake.version.major == 3 && handshake.version.minor >= 1
		&& handshake.version.minor <= 3;
}

bool handshakeHasSupportedType(const TLSHandshake& handshake)
{
	return handshake.type == TLSHandshakeHeader::Type::CLIENT_HELLO
		|| handshake.type == TLSHandshakeHeader::Type::SERVER_HELLO;
}

constexpr static
std::optional<HandshakeHeader>
parseHandshake(std::span<const std::byte> payload) noexcept
{
	const auto* handshake
		= reinterpret_cast<const HandshakeHeader*>(payload.data());

	if (sizeof(HandshakeHeader) > payload.size()) {
		return std::nullopt;
	}
	if (!handshakeHasSupportedType(*handshake)) {
		return std::nullopt;
	}
	if (!handshakeHasSupportedVersion(*handshake)) {
		return std::nullopt;
	}

	return *handshake;
}

constexpr static
std::optional<boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS>>
parseCipherSuites(std::span<const std::byte> payload,
	const TLSHandshake& handshake) noexcept
{
	auto res = std::make_optional<boost::container::static_vector<
		uint16_t, MAX_TLS_EXTENSIONS>>();
		
	if (payload.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

	if (handshake.type == TLSHandshakeHeader::Type::SERVER_HELLO) {
		return boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS>{};
	}

	// Else parse Client Hello
	const uint16_t clientCipherSuitesLength
		= ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
	if (sizeof(clientCipherSuitesLength) + clientCipherSuitesLength > payload.size()) {
		return false;
	}

	std::copy(toSpan<const uint16_t>(
		payload.data() + sizeof(clientCipherSuitesLength), clientCipherSuitesLength) |
		std::views::transform(ntohs) | 
		std::views::filter(std::not_fn(isGreaseValue)) |
		std::views::take(res->capacity()),
		std::back_inserter(*res));

	return res;
}

constexpr
std::optional<ServerNames>
TLSParser::parseServerNames(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<ServerNames>();

	if (extension.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

	const uint16_t servernameListLength
		= ntohs(*reinterpret_cast<const uint16_t*>(extension.data()));
	if (sizeof(servernameListLength) + servernameListLength > extension.size()) {
		return std::nullopt;
	}

	PrefixedLengthStringReader<uint16_t> reader(
		extension.subspan(sizeof(servernameListLength), servernameListLength));
	std::copy(reader |
		std::views::take(res->capacity()),
		std::back_inserter(*res));
	if (!reader.parsedSuccessfully()) {
		return std::nullopt;
	}
		// m_objects_parsed++;

	return res;
}

constexpr
std::optional<TLSParser::UserAgents>
TLSParser::parseUserAgent(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<UserAgents>();

	UserAgentReader reader(extension);
	std::copy(reader | 
	std::views::transform([](const UserAgent& userAgent) {
		return userAgent.value;
	}) | 
	std::views::take(res->capacity()), 
	std::back_inserter(*res));
	if (!reader.parsedSuccessfully()) {
		return std::nullopt;
	}

	return res;
}

constexpr
std::optional<TLSParser::SupportedGroups>
TLSParser::parseSupportedGroups(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<SupportedGroups>();

	if (sizeof(uint16_t) > extension.size()) {
		return std::nullopt;
	}
	const uint16_t supportedGroupsLength
		= ntohs(*reinterpret_cast<const uint16_t*>(extension.data()));
	if (sizeof(supportedGroupsLength) + supportedGroupsLength > extension.size()) {
		return std::nullopt;
	}

	std::copy(toSpan<const uint16_t>(
		reinterpret_cast<const uint16_t*>(extension.data() + sizeof(supportedGroupsLength)),
		supportedGroupsLength / sizeof(uint16_t)) | 
		std::views::transform(ntohs) | 
		std::views::filter(std::not_fn(isGreaseValue)) |
		std::views::take(res->capacity()),
		std::back_inserter(*res));

	return res;
}

constexpr
std::optional<EllipticCurvePointFormats>
TLSParser::parseEllipticCurvePointFormats(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<EllipticCurvePointFormats>();

	if (sizeof(uint8_t) > extension.size()) {
		return std::nullopt;
	}
	
	const uint8_t supportedFormatsLength 
		= *reinterpret_cast<const uint8_t*>(extension.data());
	if (sizeof(supportedFormatsLength) + supportedFormatsLength > extension.size()) {
		return std::nullopt;
	}

	std::copy(toSpan<const uint8_t>(
		extension.data() + sizeof(supportedFormatsLength),
		supportedFormatsLength) | 
		std::views::filter(std::not_fn(isGreaseValue)) |
		std::views::take(res->capacity()),
		std::back_inserter(*res));

	return res;
}

constexpr
std::optional<TLSParser::ALPNs>
TLSParser::parseALPN(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<ALPNs>();

	if (sizeof(uint16_t) > extension.size()) {
		return std::nullopt;
	}
	const uint16_t alpnExtensionLength
		= ntohs(*reinterpret_cast<const uint16_t*>(extension.data()));
	if (sizeof(alpnExtensionLength) + alpnExtensionLength > extension.size()) {
		return std::nullopt;
	}

	PrefixedLengthStringReader<uint8_t> reader(extension.subspan(
		sizeof(alpnExtensionLength), alpnExtensionLength));
	std::copy(reader | std::views::take(res->capacity()),
		std::back_inserter(*res));
	if (!reader.parsedSuccessfully()) {
		return std::nullopt;
	}

	return res;
}

std::optional<TLSParser::SignatureAlgorithms>
TLSParser::parseSignatureAlgorithms(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<SignatureAlgorithms>();

	res->insert(res->end(), toSpan<const uint16_t>(
		extension.data(), extension.size()) | 
		std::views::transform(ntohs) | 
		std::views::take(res->capacity()));

	return res;
}

constexpr
std::optional<TLSParser::SupportedVersions>
TLSParser::parseSupportedVersions(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<SupportedVersions>();

	if (m_handshake->type == TLSHandshakeHeader::Type::ServerHello) {
		if (sizeof(uint16_t) > extension.size()) {
			return std::nullopt;
		}
		res->push_back(ntohs(*reinterpret_cast<const uint16_t*>(extension.data())));
		return res;
	}

	// Else parse client hello
	if (extensions.empty()) {
		return std::nullopt;
	}
	const uint8_t versionsLength = *reinterpret_cast<const uint8_t*>(extension.data());
	if (sizeof(uint8_t) + versionsLength > extension.size()) {
		return std::nullopt;
	}
	std::ranges::copy(toSpan<const uint16_t>(
		extension.data() + sizeof(versionsLength), versionsLength / 2) | 
		std::views::transform(std::not_fn(isGreaseValue)),
		std::back_inserter(*res));

	return res;
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
