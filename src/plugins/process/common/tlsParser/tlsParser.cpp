/**
 * @file
 * @brief Class for parsing TLS traffic.
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Zainullin Damir <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "tlsParser.hpp"

#include "extensionReaders/extensionReader.hpp"
#include "extensionReaders/serverNameReader.hpp"
#include "extensionReaders/userAgentReader.hpp"
#include "tlsHandshake.hpp"
#include "tlsHeader.hpp"

#include <algorithm>
#include <functional>

#include <endian.h>
#include <readers/prefixedLengthStringReader/prefixedLengthStringReader.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp::process {

bool TLSParser::isGreaseValue(const uint16_t value) noexcept
{
	return value != 0 && !(value & ~(0xFAFA)) && ((0x00FF & value) == (value >> 8));
}

bool TLSParser::parseHello(std::span<const std::byte> payload) noexcept
{
	return parse(payload, false);
}

bool TLSParser::parseHelloFromQUIC(std::span<const std::byte> payload) noexcept
{
	return parse(payload, true);
}

constexpr static std::optional<uint8_t>
getSessionIdSectionLength(std::span<const std::byte> payload) noexcept
{
	constexpr std::size_t maxSessionIdLength = 32;
	if (payload.empty()) {
		return std::nullopt;
	}

	const uint8_t sessionIdLength = static_cast<uint8_t>(payload[0]);
	if (payload.size() < sizeof(sessionIdLength) + sessionIdLength
		|| sessionIdLength > maxSessionIdLength) {
		return std::nullopt;
	}

	return sessionIdLength + sizeof(sessionIdLength);
}

constexpr static std::optional<std::size_t> getCompressionMethodsLength(
	std::span<const std::byte> payload,
	const TLSHandshake& handshake) noexcept
{
	if (payload.empty()) {
		return std::nullopt;
	}

	if (handshake.type == TLSHandshake::Type::SERVER_HELLO) {
		return sizeof(uint8_t);
	}

	// Else parse Client Hello
	const uint8_t compressionMethodsLength = *reinterpret_cast<const uint8_t*>(payload.data());
	if (sizeof(compressionMethodsLength) + compressionMethodsLength > payload.size()) {
		return std::nullopt;
	}

	return sizeof(compressionMethodsLength) + compressionMethodsLength;
}

constexpr static std::optional<std::size_t>
parseHeader(std::span<const std::byte> payload, const bool isQUIC) noexcept
{
	if (isQUIC) {
		return 0;
	}

	if (sizeof(TLSHeader) > payload.size()) {
		return std::nullopt;
	}
	const auto* tlsHeader = reinterpret_cast<const TLSHeader*>(payload.data());

	if (tlsHeader->type != TLSHeader::Type::HANDSHAKE) {
		return std::nullopt;
	}

	if (tlsHeader->version.major != 3 || tlsHeader->version.minor > 3) {
		return std::nullopt;
	}

	return sizeof(TLSHeader);
}

bool TLSParser::parseExtensions(const std::function<bool(const TLSExtension&)>& callable) noexcept
{
	if (!m_extensions.has_value()) {
		return false;
	}

	ExtensionReader reader;
	return std::ranges::all_of(reader.getRange(*m_extensions), callable)
		&& reader.parsedSuccessfully();
}

constexpr static std::optional<std::span<const std::byte>>
getExtensionsSection(std::span<const std::byte> payload) noexcept
{
	if (payload.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

	const uint16_t extensionsLength = ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
	if (payload.size() < extensionsLength + sizeof(extensionsLength)) {
		return std::nullopt;
	}

	return payload.subspan(sizeof(extensionsLength), extensionsLength);
}

constexpr static bool handshakeHasSupportedVersion(const TLSHandshake& handshake) noexcept
{
	return handshake.version.major == 3 && handshake.version.minor >= 1
		&& handshake.version.minor <= 3;
}

constexpr static bool handshakeHasSupportedType(const TLSHandshake& handshake) noexcept
{
	return handshake.type == TLSHandshake::Type::CLIENT_HELLO
		|| handshake.type == TLSHandshake::Type::SERVER_HELLO;
}

static std::optional<TLSHandshake> parseHandshake(std::span<const std::byte> payload) noexcept
{
	const auto* handshake = reinterpret_cast<const TLSHandshake*>(payload.data());

	if (sizeof(TLSHandshake) > payload.size()) {
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

struct ParsedCipherSuitesSection {
	TLSParser::CipherSuites cipherSuites;
	std::size_t sectionLength;
};

constexpr static std::optional<ParsedCipherSuitesSection> parseClientCipherSuites(
	std::span<const std::byte> payload,
	const TLSHandshake::Type handshakeType) noexcept
{
	auto res = std::make_optional<ParsedCipherSuitesSection>();

	if (payload.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

	if (handshakeType == TLSHandshake::Type::SERVER_HELLO) {
		res->sectionLength = sizeof(uint16_t);
		return res;
	}

	const uint16_t clientCipherSuitesLength
		= ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
	if (sizeof(clientCipherSuitesLength) + clientCipherSuitesLength > payload.size()) {
		return std::nullopt;
	}

	std::ranges::copy(
		toSpan<const uint16_t>(
			payload.data() + sizeof(clientCipherSuitesLength),
			clientCipherSuitesLength / sizeof(uint16_t))
			| std::views::transform(ntohs)
			| std::views::filter(std::not_fn(TLSParser::isGreaseValue))
			| std::views::take(res->cipherSuites.capacity()),
		std::back_inserter(res->cipherSuites));

	res->sectionLength = sizeof(clientCipherSuitesLength) + clientCipherSuitesLength;

	return res;
}

bool TLSParser::parse(std::span<const std::byte> payload, const bool isQUIC) noexcept
{
	const std::optional<std::size_t> headerLength = parseHeader(payload, isQUIC);
	if (!headerLength) {
		return false;
	}

	const std::size_t handshakeOffset = *headerLength;
	handshake = parseHandshake(payload.subspan(handshakeOffset));
	if (!handshake) {
		return false;
	}

	constexpr std::size_t randomBytesLength = 32;
	const std::size_t sessionIdLengthOffset
		= handshakeOffset + sizeof(TLSHandshake) + randomBytesLength;
	if (payload.size() < sessionIdLengthOffset) {
		return false;
	}

	const std::optional<uint8_t> sessionIdSectionLength
		= getSessionIdSectionLength(payload.subspan(sessionIdLengthOffset));
	if (!sessionIdSectionLength) {
		return false;
	}

	const std::size_t cipherSuitesOffset = sessionIdLengthOffset + *sessionIdSectionLength;
	const std::optional<ParsedCipherSuitesSection> parsedCipherSuitesSection
		= parseClientCipherSuites(payload.subspan(cipherSuitesOffset), handshake->type);
	if (!parsedCipherSuitesSection.has_value()) {
		return false;
	}
	cipherSuites = parsedCipherSuitesSection->cipherSuites;

	const std::size_t compressionMethodsOffset
		= cipherSuitesOffset + parsedCipherSuitesSection->sectionLength;
	const std::optional<std::size_t> compressionMethodsLength
		= getCompressionMethodsLength(payload.subspan(compressionMethodsOffset), *handshake);
	if (!compressionMethodsLength.has_value()) {
		return false;
	}

	if (compressionMethodsOffset + *compressionMethodsLength > payload.size()) {
		return false;
	}

	m_extensions = getExtensionsSection(
		payload.subspan(compressionMethodsOffset + *compressionMethodsLength));
	if (!m_extensions.has_value()) {
		return false;
	}

	return true;
}

std::optional<TLSParser::ServerNames>
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

	ServerNameReader reader;
	std::ranges::copy(
		reader.getRange(extension.subspan(sizeof(servernameListLength), servernameListLength))
			| std::views::take(res->capacity()),
		std::back_inserter(*res));
	if (!reader.parsedSuccessfully()) {
		return std::nullopt;
	}

	return res;
}

std::optional<TLSParser::UserAgents>
TLSParser::parseUserAgent(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<UserAgents>();

	UserAgentReader reader;

	constexpr static std::size_t GOOGLE_USER_AGENT_ID = 12585;
	std::ranges::copy(
		reader.getRange(extension) | std::views::filter([](const UserAgent& userAgent) {
			return userAgent.id == GOOGLE_USER_AGENT_ID;
		}) | std::views::transform([](const UserAgent& userAgent) { return userAgent.value; })
			| std::views::take(res->capacity()),
		std::back_inserter(*res));
	if (!reader.parsedSuccessfully()) {
		return std::nullopt;
	}

	return res;
}

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

	std::ranges::copy(
		toSpan<const uint16_t>(
			reinterpret_cast<const uint16_t*>(extension.data() + sizeof(supportedGroupsLength)),
			supportedGroupsLength / sizeof(uint16_t))
			| std::views::transform(ntohs) | std::views::filter(std::not_fn(isGreaseValue))
			| std::views::take(res->capacity()),
		std::back_inserter(*res));

	return res;
}

std::optional<TLSParser::EllipticCurvePointFormats>
TLSParser::parseEllipticCurvePointFormats(std::span<const std::byte> extension) noexcept
{
	auto res = std::make_optional<TLSParser::EllipticCurvePointFormats>();

	if (sizeof(uint8_t) > extension.size()) {
		return std::nullopt;
	}

	const uint8_t supportedFormatsLength = *reinterpret_cast<const uint8_t*>(extension.data());
	if (sizeof(supportedFormatsLength) + supportedFormatsLength > extension.size()) {
		return std::nullopt;
	}

	std::ranges::copy(
		toSpan<const uint8_t>(
			extension.data() + sizeof(supportedFormatsLength),
			supportedFormatsLength)
			| std::views::filter(std::not_fn(isGreaseValue)) | std::views::take(res->capacity()),
		std::back_inserter(*res));

	return res;
}

std::optional<TLSParser::ALPNs> TLSParser::parseALPN(std::span<const std::byte> extension) noexcept
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

	PrefixedLengthStringReader<uint8_t> reader;
	std::ranges::copy(
		reader.getRange(extension.subspan(sizeof(alpnExtensionLength), alpnExtensionLength))
			| std::views::take(res->capacity()),
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

	std::ranges::copy(
		toSpan<const uint16_t>(extension.data(), extension.size() / sizeof(uint16_t))
			| std::views::transform(ntohs) | std::views::take(res->capacity()),
		std::back_inserter(*res));

	return res;
}

std::optional<TLSParser::SupportedVersions> TLSParser::parseSupportedVersions(
	std::span<const std::byte> extension,
	const TLSHandshake& handshake) noexcept
{
	auto res = std::make_optional<SupportedVersions>();

	if (handshake.type == TLSHandshake::Type::SERVER_HELLO) {
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

	std::ranges::copy(
		toSpan<const uint16_t>(
			extension.data() + sizeof(versionsLength),
			versionsLength / sizeof(uint16_t))
			| std::views::filter(std::not_fn(isGreaseValue)) | std::views::transform(ntohs)
			| std::views::take(res->capacity()),
		std::back_inserter(*res));

	return res;
}

bool TLSParser::isClientHello() const noexcept
{
	return handshake->type == TLSHandshake::Type::CLIENT_HELLO;
}

bool TLSParser::isServerHello() const noexcept
{
	return handshake->type == TLSHandshake::Type::SERVER_HELLO;
}

} // namespace ipxp::process
