/**
 * @file
 * @brief HTTP parser class definition
 * @author Zainullin Damir <zaidamilda@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "httpParser.hpp"

#include <algorithm>
#include <functional>
#include <unordered_map>

#include <utils/stringViewUtils.hpp>
#include <readers/headerFieldReader/headerFieldReader.hpp>

namespace ipxp {

constexpr static 
std::string_view removeLeadingWhitespaces(std::string_view label) noexcept
{
	const size_t firstNonWhitespace = label.find_first_not_of(' ');
	return label.substr(firstNonWhitespace);
}


constexpr static 
bool isValidHTTPMethod(std::string_view payload) noexcept
{
	constexpr std::array<std::string_view, 9> validMethods
		= {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

	return std::ranges::any_of(validMethods, 
        [method](const std::string_view& method) {
            return toStringView(payload).starts_with(method);
	    });
}

constexpr static 
bool hasHTTPVersionInRequest(std::string_view payload) noexcept
{
	constexpr std::string_view httpLabel = "HTTP";

    auto spaces = payload | std::filter([](const char c) { return c == ' '; });

    auto httpLabelBegin = std::advance(spaces.begin(), 2);
    auto httpLabelEnd = std::advance(spaces.begin(), 3);
    if (httpLabelBegin == spaces.end() || httpLabelEnd == spaces.end()) {
        return false;
    }

    return std::string_view(
        std::next(httpLabelBegin), httpLabelEnd) == httpLabel;
}

constexpr static 
bool isRequest(std::string_view payload) noexcept
{
	return isValidHTTPMethod(payload) || hasHTTPVersionInRequest(payload);
}

constexpr static 
bool hasHttpVersionInResponse(std::string_view payload) noexcept
{
	constexpr std::string_view httpLabel = "HTTP";
    return payload.starts_with(httpLabel);
}

constexpr static 
bool isResponse(std::string_view payload) noexcept
{
	return hasHttpVersionInResponse(payload);
}

constexpr
bool HTTPParser::parse(std::span<const std::byte> payload) noexcept
{
	std::string_view payload = toStringView(payload);
    
	if (isRequest(payload)) {
		return requestParsed = parseRequest(payload);
	}

	if (isResponse(payload)) {
		return responseParsed = parseResponse(payload);
	}

	return false;
}

constexpr
bool HTTPParser::parseRequestHeaders(std::string_view payload) noexcept
{
    HeaderFieldReader reader(toSpan<const std::byte>(payload));
    for (const auto& [key, value] : reader) {
        if (key == "Host") {
            host = value;
        }
        if (key == "User-Agent") {
            userAgent = value;
        }
        if (key == "Referer") {
            referer = value;
        }
    }
}

constexpr
bool HTTPParser::parseRequest(std::string_view payload) noexcept
{
	const std::size_t methodEnd = payload.find(' ');
	if (methodEnd == std::string_view::npos) {
		return false;
	}
	method = std::string_view(
        payload.substr(0, methodEnd) | std::views::drop_while(std::isspace));

	const std::size_t uriEnd = payload.find(' ', methodEnd + 1);
	if (uriEnd == std::string_view::npos) {
		return false;
	}
	uri = std::string_view(
        payload.substr(methodEnd + 1, uriEnd - methodEnd - 1) | 
        std::views::drop_while(std::isspace));

	const std::size_t httpVersionEnd = payload.find('\n', uriEnd + 1);
	if (httpVersionEnd == std::string_view::npos) {
		return false;
	}

	return parseRequestHeaders(payload.substr(httpVersionEnd + 1));
}

constexpr
bool HTTPParser::parseResponseHeaders(std::string_view payload) noexcept
{
    HeaderFieldReader reader(toSpan<const std::byte>(payload));
    for (const auto& [key, value] : reader) {
        if (key == "Content-Type") {
            contentType = value;
        }
        if (key == "Server") {
            server = value;
        }
        if (key == "Set-Cookie") {
            if (!cookies.has_value()) {
                cookies.emplace();
            }
            std::ranges::copy(splitToVector(value) | 
                std::views::transform(removeLeadingWhitespaces) |
                std::views::take(m_cookies->capacity() - m_cookies->size()),
                std::back_inserter(*m_cookies));
        }
    }
}

constexpr
bool HttpParser::parseResponse(std::string_view payload) noexcept
{
    auto spaces = payload | std::filter([](const char c) { return c == ' '; });

    auto statusCodeBegin = std::advance(spaces.begin(), 1);
    auto statusCodeEnd = std::advance(spaces.begin(), 2);
    if (statusCodeBegin == spaces.end() || statusCodeEnd == spaces.end()) {
        return false;
    }
    const auto [_, errorCode] 
        = std::from_chars(statusCodeBegin, statusCodeEnd, m_statusCode);
    if (errorCode != std::errc()) {
        return false;
    }

	const size_t statusMessageEnd = payload.find('\n', statusCodeEnd + 1);
	if (statusMessageEnd == std::string_view::npos) {
		return false;
	}

	return parseResponseHeaders(payload.substr(statusMessageEnd + 1));
}

} // namespace ipxp
