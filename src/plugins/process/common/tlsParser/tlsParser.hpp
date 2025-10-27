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

#pragma once

#include "tlsExtension.hpp"
#include "tlsHandshake.hpp"
#include "tlsVersion.hpp"

#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <boost/container/static_vector.hpp>
#include <boost/static_string.hpp>

// #include <ipfixprobe/processPlugin.hpp>

// #define TLS_HANDSHAKE_CLIENT_HELLO 1
// #define TLS_HANDSHAKE_SERVER_HELLO 2
// #define TLS_EXT_SERVER_NAME 0
// #define TLS_EXT_ALPN 16
//  draf-33, draft-34 a rfc9001, have this value defined as 0x39 == 57
// #define TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1 0x39
//  draf-13 az draft-32 have this value defined as 0xffa5 == 65445
// #define TLS_EXT_QUIC_TRANSPORT_PARAMETERS 0xffa5
//  draf-02 az draft-12 have this value defined as 0x26 == 38
// #define TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2 0x26
// #define TLS_EXT_GOOGLE_USER_AGENT 0x3129
// #define MAX_TLS_EXT_LEN 30UL

/*#define TLS_EXT_SERVER_NAME 0
#define TLS_EXT_ECLIPTIC_CURVES 10 // AKA supported_groups
#define TLS_EXT_EC_POINT_FORMATS 11
#define TLS_EXT_SIGNATURE_ALGORITHMS 13
#define TLS_EXT_ALPN 16
#define TLS_EXT_SUPPORTED_VER 43*/

namespace ipxp::process {

// #define TLS_HANDSHAKE 22

class TLSParser {
public:
	constexpr static std::size_t MAX_CIPHER_SUITES = 30;
	using CipherSuites = boost::container::static_vector<uint16_t, TLSParser::MAX_CIPHER_SUITES>;

	constexpr static std::size_t MAX_ELLIPTIC_CURVE_POINT_FORMATS = 20;
	using EllipticCurvePointFormats
		= boost::container::static_vector<uint8_t, TLSParser::MAX_ELLIPTIC_CURVE_POINT_FORMATS>;

	constexpr static std::size_t MAX_SERVER_NAMES = 10;
	using ServerNames
		= boost::container::static_vector<std::string_view, TLSParser::MAX_SERVER_NAMES>;

	constexpr static std::size_t MAX_USER_AGENTS = 10;
	using UserAgents
		= boost::container::static_vector<std::string_view, TLSParser::MAX_USER_AGENTS>;

	constexpr static std::size_t MAX_ALPNS = 20;
	using ALPNs = boost::container::static_vector<std::string_view, TLSParser::MAX_ALPNS>;

	constexpr static std::size_t MAX_SIGNATURE_ALGORITHMS = 10;
	using SignatureAlgorithms
		= boost::container::static_vector<uint16_t, TLSParser::MAX_SIGNATURE_ALGORITHMS>;

	constexpr static std::size_t MAX_SUPPORTED_VERSIONS = 20;
	using SupportedVersions
		= boost::container::static_vector<uint16_t, TLSParser::MAX_SUPPORTED_VERSIONS>;

	constexpr static std::size_t MAX_SUPPORTED_GROUPS = 20;
	using SupportedGroups
		= boost::container::static_vector<uint16_t, TLSParser::MAX_SUPPORTED_GROUPS>;

	static bool isGreaseValue(const uint16_t value) noexcept;

	bool parseHello(std::span<const std::byte> payload) noexcept;

	bool parseHelloFromQUIC(std::span<const std::byte> payload) noexcept;

	bool parseExtensions(const std::function<bool(const TLSExtension&)>& callable) noexcept;

	static std::optional<ServerNames>
	parseServerNames(std::span<const std::byte> extension) noexcept;

	static std::optional<TLSParser::UserAgents>
	parseUserAgent(std::span<const std::byte> extension) noexcept;

	static std::optional<TLSParser::SupportedGroups>
	parseSupportedGroups(std::span<const std::byte> extension) noexcept;

	static std::optional<EllipticCurvePointFormats>
	parseEllipticCurvePointFormats(std::span<const std::byte> extension) noexcept;

	static std::optional<TLSParser::ALPNs> parseALPN(std::span<const std::byte> extension) noexcept;

	static std::optional<TLSParser::SignatureAlgorithms>
	parseSignatureAlgorithms(std::span<const std::byte> extension) noexcept;

	static std::optional<TLSParser::SupportedVersions> parseSupportedVersions(
		std::span<const std::byte> extension,
		const TLSHandshake& handshake) noexcept;

	bool isClientHello() const noexcept;

	bool isServerHello() const noexcept;

	// constexpr const TLSHandshake& getHandshake() const noexcept;

	//	constexpr const CipherSuites& getCipherSuites() const noexcept;

	bool parse(std::span<const std::byte> payload, const bool isQUIC) noexcept;

	std::optional<TLSHandshake> handshake;
	std::optional<CipherSuites> cipherSuites;

	std::optional<std::span<const std::byte>> m_extensions;
};
} // namespace ipxp::process
