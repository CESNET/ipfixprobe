#pragma once

#include <string_view>

#include <span>
#include <vector>
#include "../readers/rangeReader/generator.hpp"
#include <boost/container/static_vector.hpp>
namespace ipxp
{

template<typename T>
constexpr static inline 
std::string_view toStringView(const T& container) noexcept 
{
    return std::string_view(
        reinterpret_cast<const char*>(container.data()), container.size());
}

constexpr static inline 
std::string_view toStringView(const auto* data, const std::size_t size) noexcept 
{
    return std::string_view(
        reinterpret_cast<const char*>(data), size);
}

constexpr static inline
auto split(std::string_view view, const char delimiter) noexcept
{
    return Generator::generate([&view, delimiter]() mutable {
        const std::size_t delimiterPos 
            = view.find(delimiter);
        if (delimiterPos == std::string_view::npos) {
            return std::make_optional(view);
        }

        const auto token = std::make_optional<std::string_view>(
            view.substr(0, delimiterPos));

        view.remove_prefix(delimiterPos + 1);

        return token;
    }) | std::views::take_while([](const auto& token) {
        return token.has_value();
    }) | std::views::transform([](const auto& token) {
        return *token;
    });
}

static inline
std::vector<std::string_view> splitToVector(
    std::string_view view, const char delimiter = ' ') noexcept
{
    std::vector<std::string_view> res;

    auto range = split(view, delimiter);
    std::ranges::copy(
        range, std::back_inserter(res));
    return res;
}

} // namespace ipxp
