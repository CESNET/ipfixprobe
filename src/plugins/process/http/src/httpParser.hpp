/**
 * @file
 * @brief Declaration of HTTP parser class.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a parser of HTTP traffic. Extracts HTTP method, URI, host, user-agent,
 * referer, status code, content type, server, and cookies from HTTP packets.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <boost/container/static_vector.hpp>

namespace ipxp::process::http {

/**
 * @class HTTPParser
 * @brief Class for parsing HTTP packets.
 */
class HTTPParser {
	constexpr static size_t MAX_COOKIE_COUNT = 50;

public:
	/**
	 * @brief Parse given HTTP packet
	 * @param rawHttpData HTTP packet data
	 * @return True of parsed successfully, false otherwise
	 */
	bool parse(std::span<const std::byte> payload) noexcept;

	bool requestParsed {false};
	bool responseParsed {false};

	std::optional<std::string_view> method;
	std::optional<std::string_view> uri;
	std::optional<std::string_view> host;
	std::optional<std::string_view> userAgent;
	std::optional<std::string_view> referer;
	std::optional<uint16_t> statusCode;
	std::optional<std::string_view> contentType;
	std::optional<std::string_view> server;
	std::optional<boost::container::static_vector<std::string_view, MAX_COOKIE_COUNT>> cookies;

private:
	bool parseRequestHeaders(std::string_view payload) noexcept;
	constexpr bool parseRequest(std::string_view payload) noexcept;
	bool parseResponseHeaders(std::string_view payload) noexcept;
	constexpr bool parseResponse(std::string_view payload) noexcept;
};

} // namespace ipxp::process::http
