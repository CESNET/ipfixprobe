/**
 * @file
 * @brief JA4 fingerprint generation for TLS ClientHello messages.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a class that generates JA4 fingerprints for TLS ClientHello messages.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "sha256.hpp"
#include "tlsContext.hpp"

#include <bit>
#include <charconv>
#include <format>

#include <boost/static_string.hpp>
#include <tlsParser/tlsParser.hpp>
#include <utils/stringUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::tls {

constexpr std::size_t TRUNC_SIZE = 12;

constexpr static std::string_view toLabel(const uint16_t version) noexcept
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

constexpr static std::string_view
getVersionLabel(std::span<const uint16_t> supportedVersions, const TLSHandshake& handshake) noexcept
{
	if (supportedVersions.empty()) {
		return toLabel(std::bit_cast<uint16_t>(handshake.version));
	}

	return toLabel(*std::ranges::max_element(supportedVersions));
}

constexpr static char alpnByteToLabel(char byte, bool isHighNibble)
{
	if (std::isalnum(byte)) {
		return byte;
	}

	const uint8_t nibble = isHighNibble ? byte >> 4 : byte & 0x0F;
	return nibble < 0xA ? ('0' + nibble) : ('A' + nibble - 0xA);
}

static std::string_view getALPNLabel(std::span<const std::string_view> alpns)
{
	std::string alpn_label;
	if (alpns.empty() || alpns[0].empty()) {
		return "00";
	}

	static std::array<char, 2> buffer;
	std::string_view alpn = alpns[0];
	buffer[0] = alpnByteToLabel(alpn[0], true);
	buffer[1] = alpnByteToLabel(alpn.back(), false);

	return std::string_view(buffer.data(), buffer.size());
}

constexpr static inline auto rangeToHexString
	= std::views::transform([](const auto& value) mutable {
		  static std::array<char, 6> buffer;
		  auto end = std::format_to(buffer.begin(), "{:04x},", value);
		  return std::string_view(buffer.begin(), end);
	  });

static std::string_view getTruncatedHashHex(std::string_view input)
{
	static boost::static_string<TRUNC_SIZE> buffer;

	constexpr std::size_t sha256HashSize = 32;
	std::array<uint8_t, sha256HashSize> hash {};
	hash_it(reinterpret_cast<const uint8_t*>(input.data()), input.length(), hash.data());

	std::ranges::copy(
		hash | std::views::take(buffer.size() / 2) | std::views::transform([](const uint8_t byte) {
			return std::format("{:02x}", byte);
		}) | std::views::join,
		std::back_inserter(buffer));
	return std::string_view(buffer.data(), buffer.size());
}

static std::string_view getTruncatedCipherHash(std::span<const uint16_t> cipherSuites)
{
	if (cipherSuites.empty()) {
		static const std::array<char, TRUNC_SIZE> emptyCiphers {0};
		return std::string_view(emptyCiphers.data(), emptyCiphers.size());
	}

	std::vector<uint16_t> sortedCipherSuites(cipherSuites.begin(), cipherSuites.end());
	std::ranges::sort(sortedCipherSuites);

	std::string cipherHexString;
	std::ranges::copy(
		sortedCipherSuites | rangeToHexString | std::views::join,
		std::back_inserter(cipherHexString));
	return getTruncatedHashHex(cipherHexString);
}

static std::string_view getTruncatedExtensionsHash(
	std::span<const uint16_t> extensionTypes,
	std::span<const uint16_t> signatureAlgorithms)
{
	constexpr std::size_t MAX_EXTENSIONS = 100;
	boost::container::static_vector<uint16_t, MAX_EXTENSIONS> sortedExtensions;
	std::ranges::copy(
		extensionTypes | std::views::filter([](const uint16_t type) {
			return type != static_cast<uint16_t>(TLSExtensionType::ALPN)
				&& type != static_cast<uint16_t>(TLSExtensionType::SERVER_NAME)
				&& !TLSParser::isGreaseValue(type);
		}) | std::views::take(sortedExtensions.capacity()),
		std::back_inserter(sortedExtensions));
	std::ranges::sort(sortedExtensions);

	constexpr std::size_t MAX_STRING_LENGTH = 2 * MAX_EXTENSIONS * sizeof(uint16_t) + 1;
	boost::static_string<MAX_STRING_LENGTH> finalString;
	concatenateRangeTo(sortedExtensions | rangeToHexString, finalString, '-', '_');
	concatenateRangeTo(
		signatureAlgorithms | std::views::drop(1) | rangeToHexString,
		finalString,
		'-');

	return getTruncatedHashHex(toStringView(finalString));
}

/**
 * @class JA4
 * @brief Generates JA4 fingerprint for TLS ClientHello messages.
 *
 * The JA4 class constructs a JA4 fingerprint string based on the provided
 * TLS ClientHello parameters, including protocol type, version, server names,
 * ALPNs, cipher suites, extension types, signature algorithms, and supported versions.
 */
class JA4 {
public:
	JA4(const uint8_t l4Protocol,
		const TLSHandshake& handshake,
		std::span<const std::string_view> serverNames,
		std::span<const std::string_view> alpns,
		std::span<const uint16_t> cipherSuites,
		std::span<const uint16_t> extensionTypes,
		std::span<const uint16_t> signatureAlgorithms,
		std::span<const uint16_t> supportedVersions) noexcept
	{
		// TODO USE VALUES FROM DISSECTOR
		constexpr uint8_t UDP_ID = 17;
		value.push_back(l4Protocol == UDP_ID ? 'q' : 't');

		std::string_view versionLabel = getVersionLabel(supportedVersions, handshake);
		value.append(versionLabel.begin(), versionLabel.end());

		value.push_back(serverNames.empty() ? 'i' : 'd');

		value.push_back(std::min(cipherSuites.size(), 99UL));

		value.push_back(std::min(extensionTypes.size(), 99UL));

		std::string_view alpnLabel = getALPNLabel(alpns);
		value.append(alpnLabel.begin(), alpnLabel.end());

		std::string_view cipherHash = getTruncatedCipherHash(cipherSuites);
		value.append(cipherHash.begin(), cipherHash.end());

		std::string_view extensionsHash
			= getTruncatedExtensionsHash(extensionTypes, signatureAlgorithms);
		value.append(extensionsHash.begin(), extensionsHash.end());
	}

	std::string_view getView() const noexcept
	{
		return std::string_view(value.data(), value.size());
	}

private:
	boost::static_string<TLSContext::JA4_SIZE> value;
};

} // namespace ipxp::process::tls
