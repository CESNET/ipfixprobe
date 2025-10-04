/**
 * @file
 * @brief Utility functions for string manipulation and conversion.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <ranges>

namespace ipxp {

constexpr static inline auto integerToCharPtrView
	= std::views::transform([](const auto& value) mutable {
		  static std::array<char, 100> buffer;
		  auto [end, _] = std::to_chars(buffer.data(), buffer.end(), value);
		  return std::string_view(buffer.data(), end);
	  });

constexpr static inline bool
pushBackWithDelimiter(auto&& value, auto&& outputContainer, const char delimiter) noexcept
{
	if (outputContainer.size() + value.size() + sizeof(delimiter) > outputContainer.capacity()) {
		return true;
	}

	outputContainer.append(value.begin(), value.end());
	outputContainer.push_back(delimiter);

	return false;
}

constexpr static inline void concatenateRangeTo(
	auto&& inputRange,
	auto&& outputContainer,
	const char delimiter,
	const std::optional<char> terminator = std::nullopt) noexcept
{
	const bool overflowed
		= std::any_of(inputRange.begin(), inputRange.end(), [&](const auto& value) {
			  return pushBackWithDelimiter(value, outputContainer, delimiter);
		  });

	if (overflowed) {
		return;
	}

	if (terminator.has_value()) {
		outputContainer.back() = *terminator;
	} else {
		outputContainer.pop_back();
	}
}

} // namespace ipxp
