/**
 * @file
 * @author Lukas Hutak <lukas.hutak@hotmail.com>
 * @brief Telemetry content
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <iomanip>
#include <sstream>
#include <string>
#include <type_traits>

#include "content.hpp"

namespace ipxp::Telemetry {

template<typename... T>
constexpr bool g_AlwaysFalse = false;

static std::string scalarToString(const Scalar& scalar)
{
    auto converter = [](auto&& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;

        if constexpr (std::is_same_v<T, std::monostate>) {
            return "<N/A>";
        } else if constexpr (std::is_same_v<T, bool>) {
            return arg ? "true" : "false";
        } else if constexpr (std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t>) {
            return std::to_string(arg);
        } else if constexpr (std::is_same_v<T, double>) {
            std::stringstream stream;
            stream << std::fixed << std::setprecision(2) << arg;
            return stream.str();
        } else if constexpr (std::is_same_v<T, std::string>) {
            return arg;
        } else {
            static_assert(g_AlwaysFalse<T>, "non-exhaustive visitor");
        }
    };

    return std::visit(converter, scalar);
}

static std::string scalarWithUnitToString(const ScalarWithUnit& scalar)
{
    const auto& [value, unit] = scalar;
    return scalarToString(value) + " (" + unit + ")";
}

static std::string arrayToString(const Array& array)
{
    std::string result;
    size_t cnt = 0;

    result += '[';

    for (const auto& elem : array) {
        if (cnt > 0) {
            result += ", ";
        }

        result += scalarToString(elem);
        cnt++;
    }

    result += ']';
    return result;
}

static std::string dictValueToString(const DictValue& value)
{
    auto converter = [](auto&& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;

        if constexpr (std::is_same_v<T, std::monostate>) {
            return "<N/A>";
        } else if constexpr (std::is_same_v<T, Scalar>) {
            return scalarToString(arg);
        } else if constexpr (std::is_same_v<T, ScalarWithUnit>) {
            return scalarWithUnitToString(arg);
        } else if constexpr (std::is_same_v<T, Array>) {
            return arrayToString(arg);
        } else {
            static_assert(g_AlwaysFalse<T>, "non-exhaustive visitor");
        }
    };

    return std::visit(converter, value);
}

static std::string dictToString(const Dict& dict)
{
    std::stringstream result;
    size_t maxKeyLen = 0;
    size_t cnt = 0;

    for (const auto& [key, _] : dict) {
        maxKeyLen = std::max(maxKeyLen, key.length());
    }

    for (const auto& [key, value] : dict) {
        const int extraSpaces = static_cast<int>(maxKeyLen - key.length());

        if (cnt > 0) {
            result << '\n';
        }

        result << key;
        result << std::left << std::setw(2 + extraSpaces) << ':';
        result << dictValueToString(value);

        cnt++;
    }

    return result.str();
}

std::string contentToString(const Content& content)
{
    auto converter = [](auto&& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;

        if constexpr (std::is_same_v<T, Scalar>) {
            return scalarToString(arg);
        } else if constexpr (std::is_same_v<T, ScalarWithUnit>) {
            return scalarWithUnitToString(arg);
        } else if constexpr (std::is_same_v<T, Array>) {
            return arrayToString(arg);
        } else if constexpr (std::is_same_v<T, Dict>) {
            return dictToString(arg);
        } else {
            static_assert(g_AlwaysFalse<T>, "non-exhaustive visitor");
        }
    };

    return std::visit(converter, content);
}

} // namespace ipxp::Telemetry

#ifdef IPFIXEXP_ENABLE_TESTS
#include "test/TestContent.cpp"
#endif
