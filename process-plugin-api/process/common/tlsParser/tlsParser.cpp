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

//#include "tlsCipherSuite.hpp"
#include "tlsHeader.hpp"
#include "tlsHandshake.hpp"
#include "extensionReaders/extensionReader.hpp"


namespace ipxp {

constexpr bool isGreaseValue(const uint16_t value) noexcept
{
	return value != 0 && 
	!(value & ~(0xFAFA)) && 
	((0x00FF & value) == (value >> 8));
}

constexpr
bool TLSParser::parseHello(std::span<const std::byte> payload) noexcept
{
	return parse(payload, false);
}

constexpr
bool TLSParser::parseHelloFromQUIC(std::span<const std::byte> payload) noexcept
{
	return parse(payload, true);
}

constexpr static
std::optional<uint8_t> 
getSessionIdSectionLength(std::span<const std::byte> payload) noexcept
{
	constexpr std::size_t maxSessionIdLength = 32;
	if (payload.empty()) {
		return std::nullopt;
	}

	const uint8_t sessionIdLength = static_cast<uint8_t>(payload[0]);
	if (payload.size() < sizeof(sessionIdLength) + sessionIdLength ||
		sessionIdLength > maxSessionIdLength) {
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
		return 0;
	}
	const auto* tlsHeader = reinterpret_cast<const TLSHeader*>(payload.data());

	if (sizeof(TLSHeader) > payload.size()) {
		return std::nullopt;
	}

	if (tlsHeader->type != Header::Type::HANDSHAKE) {
		return std::nullopt;
	}

	if (tlsHeader->version.bytes.major != 3 || 
		tlsHeader->version.bytes.minor > 3) {
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

constexpr static
bool handshakeHasSupportedVersion(const TLSHandshake& handshake) noexcept
{
	return handshake.version.major == 3 && handshake.version.minor >= 1
		&& handshake.version.minor <= 3;
}

constexpr static
bool handshakeHasSupportedType(const TLSHandshake& handshake) noexcept
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
std::optional<boost::container::static_vector<uint16_t, MAX_CIPHER_SUITES>>
parseClientCipherSuites(std::span<const std::byte> payload,
	const TLSHandshake& handshake) noexcept
{
	auto res = std::make_optional<boost::container::static_vector<
		uint16_t, MAX_CIPHER_SUITES>>();
		
	if (payload.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

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

constexpr bool TLSParser::parse(
	std::span<const std::byte> payload, const bool isQUIC) noexcept
{
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
		m_cipherSuites = parseClientCipherSuites(payload.subspan(cipherSuitesOffset), &m_handshake);
		if (!m_cipherSuites.has_value()) {
			return false;
		}
	}

	const std::size_t compressionMethodsOffset = cipherSuitesOffset 
		+ sizeof(uint16_t) + (m_cipherSuites.has_value() 
		? m_cipherSuites->size() * sizeof(uint16_t) : 0);
	const std::optional<std::size_t> compressionMethodsLength
		= getCompressionMethodsLength(payload.subspan(compressionMethodsOffset), *handshake);
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

constexpr
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
TLSParser::parseSupportedVersions(
	std::span<const std::byte> extension, const HandshakeHeader& handshake) noexcept
{
	auto res = std::make_optional<SupportedVersions>();

	if (handshake.type == TLSHandshakeHeader::Type::ServerHello) {
		if (sizeof(uint16_t) > extension.size()) {
			return std::nullopt;
		}
		res->push_back(ntohs(*reinterpret_cast<const uint16_t*>(extension.data())));
		return res;
	}

	// Else parse client hello
	if (extension.empty()) {
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

constexpr
const HandshakeHeader& TLSParser::getHandshake() const noexcept
{
	return *m_handshake;
}

constexpr
bool TLSParser::isClientHello() const noexcept
{
	return m_handshake->type == HandshakeHeader::Type::CLIENT_HELLO;
}

constexpr
bool TLSParser::isServerHello() const noexcept
{
	return m_handshake->type == HandshakeHeader::Type::SERVER_HELLO;
}

constexpr
const CipherSuites& TLSParser::getCipherSuites() const noexcept
{
	return *m_cipherSuites;
}

} // namespace ipxp
