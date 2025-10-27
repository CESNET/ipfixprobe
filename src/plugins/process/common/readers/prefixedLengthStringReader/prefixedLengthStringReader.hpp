/**
 * @file
 * @brief Prefixed length string reader.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "../../utils/toHostByteOrder.hpp"
#include "../rangeReader/generator.hpp"
#include "../rangeReader/rangeReader.hpp"

#include <optional>
#include <ranges>
#include <span>

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
template<typename LengthType>
struct PrefixedLengthStringReader : public RangeReader {
	auto getRange(std::span<const std::byte> extension) noexcept
	{
		return Generator([this, extension]() mutable -> std::optional<std::string_view> {
			if (extension.empty()) {
				setSuccess();
				return std::nullopt;
			}

			if (extension.size() < sizeof(LengthType)) {
				return std::nullopt;
			}

			const LengthType length
				= toHostByteOrder(*reinterpret_cast<const LengthType*>(extension.data()));
			if (extension.size() < length + sizeof(length)) {
				return std::nullopt;
			}

			const auto label = reinterpret_cast<const char*>(extension.data() + sizeof(length));
			extension = extension.subspan(length + sizeof(length));

			return std::string_view(label, length);
		});
	}
};

} // namespace ipxp
