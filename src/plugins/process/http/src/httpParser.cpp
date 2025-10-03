/**
 * @file
 * @brief Definition of HTTP parser class.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a parser of HTTP traffic. Extracts HTTP method, URI, host, user-agent,
 * referer, status code, content type, server, and cookies from HTTP packets.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "httpParser.hpp"

#include <algorithm>
#include <charconv>
#include <functional>
#include <unordered_map>

#include <readers/headerFieldReader/headerFieldReader.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp {

constexpr static std::string_view removeLeadingWhitespaces(std::string_view label) noexcept
{
	const size_t firstNonWhitespace = label.find_first_not_of(' ');
	return label.substr(firstNonWhitespace);
}

constexpr static bool isValidHTTPMethod(std::string_view payload) noexcept
{
	constexpr std::array<std::string_view, 9> validMethods
		= {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

	return std::ranges::any_of(validMethods, [payload](const std::string_view& method) {
		return payload.starts_with(method);
	});
}

constexpr static bool hasHTTPVersionInRequest(std::string_view payload) noexcept
{
	constexpr std::string_view httpLabel = "HTTP";

	auto spaces = payload | std::views::filter([](const char c) { return c == ' '; });

	auto httpLabelBegin = std::ranges::next(spaces.begin(), 2);
	auto httpLabelEnd = std::ranges::next(spaces.begin(), 3);
	if (httpLabelBegin == spaces.end() || httpLabelEnd == spaces.end()) {
		return false;
	}

	return std::string_view(&*std::next(httpLabelBegin), &*httpLabelEnd) == httpLabel;
}

constexpr static bool isRequest(std::string_view payload) noexcept
{
	return isValidHTTPMethod(payload) || hasHTTPVersionInRequest(payload);
}

constexpr static bool hasHttpVersionInResponse(std::string_view payload) noexcept
{
	constexpr std::string_view httpLabel = "HTTP";
	return payload.starts_with(httpLabel);
}

constexpr static bool isResponse(std::string_view payload) noexcept
{
	return hasHttpVersionInResponse(payload);
}

bool HTTPParser::parse(std::span<const std::byte> payload) noexcept
{
	std::string_view payloadView = toStringView(payload);

	if (isRequest(payloadView)) {
		return requestParsed = parseRequest(payloadView);
	}

	if (isResponse(payloadView)) {
		return responseParsed = parseResponse(payloadView);
	}

	return false;
}

bool HTTPParser::parseRequestHeaders(std::string_view payload) noexcept
{
	HeaderFieldReader reader;
	for (const auto& [key, value] : reader.getRange(payload)) {
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

	return reader.parsedSuccessfully();
}

constexpr bool HTTPParser::parseRequest(std::string_view payload) noexcept
{
	const std::size_t methodEnd = payload.find(' ');
	if (methodEnd == std::string_view::npos) {
		return false;
	}
	auto methodBegin
		= std::ranges::find_if(payload, [](const unsigned char c) { return !std::isspace(c); });
	const std::size_t methodBeginPos = std::distance(payload.begin(), methodBegin);
	method = std::string_view(payload.substr(methodBeginPos, methodEnd - methodBeginPos));

	const std::size_t uriEnd = payload.find(' ', methodEnd + 1);
	if (uriEnd == std::string_view::npos) {
		return false;
	}
	auto uriBegin = std::ranges::find_if(payload.substr(methodEnd + 1), [](const unsigned char c) {
		return !std::isspace(c);
	});
	const std::size_t uriBeginPos = std::distance(payload.begin(), uriBegin);
	uri = std::string_view(payload.substr(uriBeginPos, uriEnd - uriBeginPos));

	const std::size_t httpVersionEnd = payload.find('\n', uriEnd + 1);
	if (httpVersionEnd == std::string_view::npos) {
		return false;
	}

	return parseRequestHeaders(payload.substr(httpVersionEnd + 1));
}

bool HTTPParser::parseResponseHeaders(std::string_view payload) noexcept
{
	HeaderFieldReader reader;
	for (const auto& [key, value] : reader.getRange(payload)) {
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
			std::ranges::copy(
				splitToVector(value) | std::views::transform(removeLeadingWhitespaces)
					| std::views::take(cookies->capacity() - cookies->size()),
				std::back_inserter(*cookies));
		}
	}

	return reader.parsedSuccessfully();
}

constexpr bool HTTPParser::parseResponse(std::string_view payload) noexcept
{
	auto spaces = payload | std::views::filter([](const char c) { return c == ' '; });

	auto statusCodeBegin = std::next(spaces.begin(), 1);
	auto statusCodeEnd = std::next(spaces.begin(), 2);
	if (statusCodeBegin == spaces.end() || statusCodeEnd == spaces.end()) {
		return false;
	}
	const auto [_, errorCode] = std::from_chars(&*statusCodeBegin, &*statusCodeEnd, *statusCode);
	if (errorCode != std::errc()) {
		return false;
	}

	const size_t statusMessageEnd
		= payload.find('\n', std::distance(spaces.begin(), statusCodeEnd) + 1);
	if (statusMessageEnd == std::string_view::npos) {
		return false;
	}

	return parseResponseHeaders(payload.substr(statusMessageEnd + 1));
}

} // namespace ipxp
