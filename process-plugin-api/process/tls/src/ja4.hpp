#pragma once

#include <boost/static_string.hpp>
#include <charconv>

#include <tlsParser/tlsParser.hpp>
#include <utils/stringUtils.hpp>

#include "md5.hpp"

namespace ipxp
{

constexpr static
auto addComma(auto&& inputRange) noexcept
{
    return std::views::concat(inputRange, std::views::single(","));
}

constexpr static 
std::string_view toLabel(const uint16_t version) noexcept
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

constexpr static 
std::string_view getVersionLabel(
    std::span<const uint16_t> supportedVersions, const HandshakeHeader& handshake) noexcept
{
	if (supportedVersions.empty()) {
		return toLabel(
            *reinterpret_cast<const uint16_t*>(&handshake.version.version));
	}

    return toLabel(*std::ranges::max_element(supportedVersions));
}

constexpr static 
char alpnByteToLabel(char byte, bool isHighNibble)
{
	if (std::isalnum(byte)) {
		return byte;
	}

    const uint8_t nibble = isHighNibble ? byte >> 4 : byte & 0x0F;
    return nibble < 0xA ? ('0' + nibble) : ('A' + nibble - 0xA);
}

constexpr static 
std::string_view getALPNLabel(std::span<std::string_view> alpns)
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

constexpr static 
std::string get_truncated_cipher_hash(std::span<const uint16_t> cipherSuites)
{
    static std::array<char, 12> buffer;
	std::string cipher_string;
	std::vector<uint16_t> sortedCipherSuites(cipherSuites.begin(), cipherSuites.end());
	std::ranges::sort(sortedCipherSuites);

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

class JA4 {
public:
    constexpr
    JA4(const uint8_t l4Protocol,
        const HandshakeHeader& handshake,
        std::span<std::string_view> serverNames,
        std::span<std::string_view> alpns,
        std::span<const uint16_t> supportedGroups,
        std::span<const uint8_t> pointFormats
    )
    {
    // TODO USE VALUES FROM DISSECTOR
	constexpr uint8_t UDP_ID = 17;
	const char protocol = l4Protocol == UDP_ID ? 'q' : 't';

	std::string_view versionLabel 
        = getVersionLabel(supportedVersions, handshake);

	const char sniLabel = serverNames.empty() ? 'i' : 'd';

	const uint8_t ciphers_count = std::min(parser.get_cipher_suits().size(), 99UL);

	const uint8_t extension_count = std::min(parser.get_extensions().size(), 99UL);

	const auto alpnLabel = getALPNLabel(alpns);

	const auto truncated_cipher_hash = get_truncated_cipher_hash(parser);

	const auto truncated_extensions_hash = get_truncated_extensions_hash(parser);

	return std::string {} + protocol + version_label + sni_label + std::to_string(ciphers_count)
		+ std::to_string(extension_count) + alpn_label + '_' + truncated_cipher_hash + '_'
		+ truncated_extensions_hash;
    }

    std::string_view getHash() const noexcept {
        return std::string_view(hash.data(), hash.size());
    }

private:
    std::array<char, 16> hash
};
    
} // namespace ipxp
