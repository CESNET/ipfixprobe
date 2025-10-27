/**
 * @file
 * @brief Utility functions for working with spans.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <array>
#include <cstddef>
#include <span>

namespace ipxp {

/*template<typename SpanElementType = void, typename Container>
constexpr static inline
auto getSpan(const Container& container) noexcept
{
	 using ElementType = std::conditional_t<
		std::is_void_v<SpanElementType>,
		const typename Container::value_type,
		SpanElementType
	>;

	static_assert(
		std::is_const_v<ElementType>,
		"SpanElementType must be a const type"
	);

	return std::span<ElementType>(reinterpret_cast<ElementType*>(
		container.data()), container.size());
}*/

/*
template<typename ElementType, std::size_t Size>
constexpr static inline
std::span<ElementType> toSpan(const std::array<ElementType, Size>& arr)
{
	return std::span<ElementType>(arr);
}*/

template<typename ElementType>
constexpr static inline std::span<ElementType> toSpan(const auto& container) noexcept
{
	return std::span<ElementType>(
		reinterpret_cast<ElementType*>(container.data()),
		container.size());
}

template<typename ElementType>
constexpr static inline std::span<ElementType> toSpan(const auto* data, const std::size_t size)
{
	return std::span<ElementType>(reinterpret_cast<ElementType*>(data), size);
}

} // namespace ipxp
