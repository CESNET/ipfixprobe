#pragma once

#include <views>

namespace ipxp
{

constexpr static inline auto integerToCharPtrView = std::views::transform(
    [](const auto& value) mutable {
        static std::array<char, 100> buffer;
        auto [end, _] = std::to_chars(buffer.data(), buffer.end(), value);
        *end = 0;
        return buffer.data();
    });

constexpr static
void concatenateRangeTo(
    auto&& inputRange, auto&& outputContainer, const char delimiter) noexcept
{
    bool overflowed = false;
	std::ranges::for_each(inputRange, [&outputContainer, &overflowed](const auto& value) {
		if (outputContainer.size() + value.size() + sizeof(delimiter) 
			> outputContainer.capacity()) {
			overflowed = true;
			return;
		}
		outputContainer.push_back(value);
		outputContainer.push_back(delimiter);
	});

    if (!outputContainer.empty()) {
        outputContainer.pop_back();
    }

    return overflowed;
}

} // namespace ipxp
