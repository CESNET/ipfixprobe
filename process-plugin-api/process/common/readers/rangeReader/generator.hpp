#pragma once

#include <ranges>

namespace ipxp
{

// no std::ranges::generate in c++20(from c++23)

template<typename GeneratorCallback>
class Generator {
public:

constexpr static
auto generate(auto generator) noexcept
{
    return std::views::iota(0) | 
            std::views::transform([gen = std::move(generator)](int) mutable {
               return gen();
           });
}

};

} // namespace ipxp
