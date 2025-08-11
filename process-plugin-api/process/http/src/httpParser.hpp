/**
 * @file
 * @brief HTTP parser class declaration
 * @author Zainullin Damir <zaidamilda@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <boost/container/static_vector.hpp>

namespace ipxp2 {

/**
 * @brief HTTP parser class
 */
class HTTPParser {
	constexpr static size_t MAX_COOKIE_COUNT = 50;

public:
	/**
	 * @brief Parse given HTTP packet
	 * @param rawHttpData HTTP packet data
	 * @return True of parsed successfully, false otherwise
	 */
	constexpr bool parse(std::span<const std::byte> payload) noexcept;

    bool requestParsed{false};
    bool responseParsed{false};

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
	constexpr bool parseRequestHeaders(std::string_view payload) noexcept;
	constexpr bool parseRequest(std::string_view payload) noexcept;
    constexpr bool parseResponseHeaders(std::string_view payload) noexcept;
    constexpr bool parseResponse(std::string_view payload) noexcept;
};

} // namespace ipxp2
