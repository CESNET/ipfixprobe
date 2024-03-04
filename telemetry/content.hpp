/**
 * @file
 * @author Lukas Hutak <lukas.hutak@hotmail.com>
 * @brief Telemetry content
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <map>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace ipxp::Telemetry {

/** @brief Scalar type returned by file read operations. */
using Scalar = std::variant<std::monostate, bool, uint64_t, int64_t, double, std::string>;
/** @brief Scalar type with unit (useful for numeric types). */
using ScalarWithUnit = std::pair<Scalar, std::string>;
/** @brief Array type returned by file read operations. */
using Array = std::vector<Scalar>;
/** @brief Dictionary key used as a part of file read operations. */
using DictKey = std::string;
/** @brief Dictionary value used as a part of file read operations. */
using DictValue = std::variant<std::monostate, Scalar, ScalarWithUnit, Array>;
/** @brief Dictionary type used by file read operations. */
using Dict = std::map<DictKey, DictValue>;
/** @brief Output of file read operation can be a scalar, an array, or a dictionary. */
using Content = std::variant<Scalar, ScalarWithUnit, Array, Dict>;

/**
 * @brief Convert telemetry @p content to human readable string.
 */
std::string contentToString(const Content& content);

} // namespace ipxp::Telemetry
