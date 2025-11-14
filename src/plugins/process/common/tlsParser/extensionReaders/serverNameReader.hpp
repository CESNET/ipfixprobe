/**
 * @file
 * @brief Prefixed length string reader.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "../../readers/rangeReader/generator.hpp"
#include "../../readers/rangeReader/rangeReader.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>

#include <arpa/inet.h>

namespace ipxp {

/**
 * @struct PrefixedLengthStringReader
 * @brief Reader for strings prefixed with their length.
 *
 * This reader extracts strings from a byte span where each string is prefixed
 * by its length of type `LengthType`. It generates a range of strings until
 * it encounters an end or fails to parse a string.
 *
 * @tparam LengthType The type used for the length prefix (e.g., uint8_t, uint16_t).
 */

struct [[gnu::packed]] ServerNameExtension {
	uint8_t type;
	uint16_t length;
};

struct ServerNameReader : public RangeReader {
	auto getRange(std::span<const std::byte> extension) noexcept
	{
		return Generator([this, extension]() mutable -> std::optional<std::string_view> {
			if (extension.empty()) {
				setSuccess();
				return std::nullopt;
			}

			if (extension.size() < sizeof(ServerNameExtension)) {
				return std::nullopt;
			}

			const ServerNameExtension* serverNameExtension
				= reinterpret_cast<const ServerNameExtension*>(extension.data());
			const uint16_t length = ntohs(serverNameExtension->length);
			if (extension.size() < length + sizeof(ServerNameExtension)) {
				return std::nullopt;
			}

			const auto label
				= reinterpret_cast<const char*>(extension.data() + sizeof(ServerNameExtension));
			extension = extension.subspan(length + sizeof(ServerNameExtension));

			return std::string_view(label, length);
		});
	}
};

} // namespace ipxp
