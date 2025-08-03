#pragma once

#include <array>
#include <span>
#include <cstddef>

namespace ipxp
{
    
template<typename ElementType, std::size_t Size>
constexpr static inline
std::span<ElementType, Size> toSpan(const std::array<ElementType, Size>& arr)
{
	return std::span<ElementType, Size>(arr);
}

template<typename ElementType>
constexpr static inline
std::span<ElementType> toSpan(const auto* data, const std::size_t size)
{
	return std::span<ElementType>(
        reinterpret_cast<ElementType*>(data), size);
}


} // namespace ipxp
