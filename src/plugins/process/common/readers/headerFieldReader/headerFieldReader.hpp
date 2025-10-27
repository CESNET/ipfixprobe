/**
 * @file
 * @brief Provides a reader for parsing header fields from protocol messages.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * This reader is common for various protocols, including RTSP, SIP, SMTP, and HTTP.
 */

#pragma once

#include <optional>
#include <ranges>
#include <span>
#include <string_view>

#include <readers/rangeReader/generator.hpp>
#include <readers/rangeReader/rangeReader.hpp>

namespace ipxp {

/**
 * @struct HeaderField
 * @brief Represents a key-value pair of a header field.
 */
struct HeaderField {
	std::string_view key;
	std::string_view value;
};

/**
 * @class HeaderFieldReader
 * @brief A reader for parsing header fields from protocol messages.
 *
 * This class provides functionality to parse header fields formatted as "Key: Value\r\n"
 * from a given payload. It uses a generator to yield each parsed header field as a
 * `HeaderField` struct.
 */
struct HeaderFieldReader : public RangeReader {
	auto getRange(std::string_view payload) noexcept
	{
		return Generator([this, payload]() mutable -> std::optional<HeaderField> {
			const std::size_t extensionEnd = payload.find("\r\n");
			if (extensionEnd == std::string_view::npos) {
				return std::nullopt;
			}

			if (extensionEnd < 2) {
				setSuccess();
				return std::nullopt;
			}

			auto delimiterPos = payload.find(':');
			if (delimiterPos < 2) {
				return std::nullopt;
			}

			std::string_view key = payload.substr(0, delimiterPos);

			std::string_view value
				= payload.substr(delimiterPos + 2, extensionEnd - delimiterPos - 2);

			payload = payload.substr(extensionEnd);

			return HeaderField {key, value};
		});
	}
};

} // namespace ipxp
