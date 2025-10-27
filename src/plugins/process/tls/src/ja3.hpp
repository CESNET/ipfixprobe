/**
 * @file
 * @brief JA3 fingerprint generation for TLS ClientHello messages.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a class that generates JA3 fingerprints for TLS ClientHello messages.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */
#pragma once

#include "md5.hpp"
#include "tlsContext.hpp"

#include <charconv>

#include <boost/static_string.hpp>
#include <tlsParser/tlsParser.hpp>
#include <utils/stringUtils.hpp>

namespace ipxp::process::tls {

/*
constexpr static
std::string concatenateJA3(auto&& inputRange, auto&& buffer) noexcept
{
	std::array<char, 20> tmp;
	concatenateRangeTo(inputRange | std::views::transform([](const auto& value) {
		return std::to_string(value);
	}), buffer, '-');
	if (vector.empty()) {
		return "";
	}
	return std::accumulate(
		std::next(vector.begin()),
		vector.end(),
		std::to_string(vector[0]),
		[](const std::string& a, uint16_t b) { return a + "-" + std::to_string(b); });
}*/

/**
 * @class JA3
 * @brief Generates JA3 fingerprint for TLS ClientHello messages.
 *
 * The JA3 class constructs a JA3 fingerprint string based on the provided
 * TLS ClientHello parameters, including protocol type, version, server names,
 * ALPNs, cipher suites, extension types, signature algorithms, and supported versions.
 */
class JA3 {
public:
	JA3(const uint16_t version,
		std::span<const uint16_t> cipherSuites,
		std::span<const uint16_t> extensionsTypes,
		std::span<const uint16_t> supportedGroups,
		std::span<const uint8_t> pointFormats)
	{
		constexpr std::size_t bufferSize = 512;
		boost::static_string<bufferSize> result;

		pushBackWithDelimiter(std::to_string(version), result, ',');

		auto cipherSuitesRange = cipherSuites | integerToCharPtrView;
		concatenateRangeTo(cipherSuitesRange, result, '-', ',');

		auto extensionsTypesRange = extensionsTypes
			| std::views::filter(std::not_fn(TLSParser::isGreaseValue)) | integerToCharPtrView;
		concatenateRangeTo(extensionsTypesRange, result, '-', ',');

		auto supportedGroupsRange = supportedGroups
			| std::views::filter(std::not_fn(TLSParser::isGreaseValue)) | integerToCharPtrView;
		concatenateRangeTo(supportedGroupsRange, result, '-', ',');

		auto pointFormatsRange = pointFormats | integerToCharPtrView;
		concatenateRangeTo(pointFormatsRange, result, '-');

		md5_get_bin(std::string_view(result.data(), result.size()), hash.data());
	}

	std::string_view getHash() const noexcept { return std::string_view(hash.data(), hash.size()); }

private:
	constexpr static std::size_t JA3_SIZE = 16;
	std::array<char, JA3_SIZE> hash;
};

} // namespace ipxp::process::tls
