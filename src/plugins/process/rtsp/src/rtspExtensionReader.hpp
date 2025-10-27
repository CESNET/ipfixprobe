/**
 * @file
 * @brief Provides RTSP extension reader to obtain key-value pairs from RTSP headers.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <optional>
#include <span>

#include <readers/rangeReader/generator.hpp>
#include <readers/rangeReader/rangeReader.hpp>

namespace ipxp::process::rtsp {

/**
 * @struct Extension
 * @brief RTSP extension key-value pair.
 */
struct Extension {
	std::string_view key;
	std::string_view value;
};

/**
 * @class RTSPExtensionReader
 * @brief Reader to obtain RTSP extensions from raw payload.
 */
class RTSPExtensionReader : public RangeReader {
public:
	auto getRange(std::string_view payload) noexcept
	{
		return Generator([this, payload]() mutable -> std::optional<Extension> {
			const std::size_t extensionEnd = payload.find('\n');
			if (extensionEnd == std::string_view::npos) {
				return std::nullopt;
			}

			if (extensionEnd < 2) {
				setSuccess();
				return std::nullopt;
			}

			const std::size_t delimiterPos = payload.find(':');
			if (delimiterPos == std::string_view::npos || payload.size() - delimiterPos < 2) {
				return std::nullopt;
			}

			std::string_view key = payload.substr(0, delimiterPos);

			std::string_view value
				= payload.substr(delimiterPos + 2, extensionEnd - delimiterPos - 2);

			payload = payload.substr(extensionEnd + 1);

			return Extension {key, value};
		});
	}
};

} // namespace ipxp::process::rtsp