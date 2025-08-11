#pragma once

#include <boost/static_string.hpp>
#include <charconv>

#include <tlsParser/tlsParser.hpp>
#include <utils/stringUtils.hpp>

#include "md5.hpp"
#include "tlsExport.hpp"

namespace ipxp
{

constexpr static
auto addComma(auto&& inputRange) noexcept
{
    return std::views::concat(inputRange, std::views::single(","));
}

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
}


constexpr static std::string
concatenate_extensions_vector_to_string(const std::vector<TLSExtension>& extensions)
{
	if (extensions.empty()) {
		return "";
	}
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

class JA3 {
public:
    constexpr
    JA3(const uint16_t version,
        std::span<const uint16_t> cipherSuites,
        std::span<const uint16_t> extensionsTypes,
        std::span<const uint16_t> supportedGroups,
        std::span<const uint8_t> pointFormats
    )
    {
        constexpr std::size_t bufferSize = 512;
        boost::static_string<bufferSize> result;

        auto versionRange = addComma(
            std::views::single(version) | integerToCharPtrView);

        auto cipherSuitesRange = addComma(
            cipherSuites | integerToCharPtrView);

        auto extensionsTypesRange = addComma(
            extensionsTypes | 
            std::not_fn(TLSParser::isGreaseValue) | 
            integerToCharPtrView);

        auto supportedGroupsRange = addComma(
            supportedGroups | integerToCharPtrView);

        std::ranges::copy({versionRange, cipherSuitesRange, 
            extensionsTypesRange, supportedGroupsRange, 
            pointFormats | integerToCharPtrView} | 
            std::views::join |
            std::views::take(result.capacity()), 
            std::back_inserter(result));

	    md5_get_bin(std::string_view(
            result.data(), result.size()), hash.data());
    }

    std::string_view getHash() const noexcept {
        return std::string_view(hash.data(), hash.size());
    }

private:
    std::array<char, JA3_SIZE> hash
};
    
} // namespace ipxp
