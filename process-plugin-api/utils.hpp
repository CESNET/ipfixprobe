#pragma once

#include <span>

namespace ipxp
{

template<typename SpanElementType = void, typename Container>
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
}

} // namespace ipxp
