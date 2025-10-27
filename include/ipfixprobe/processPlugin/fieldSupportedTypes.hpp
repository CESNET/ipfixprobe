/**
 * @file
 * @author Pavel Siska
 * @brief Definitions of supported scalar and vector field type lists.
 *
 * This header defines central compile-time type lists of fundamental numeric,
 * application-specific, textual, and binary field types.
 *
 * These lists are used for:
 * - Type validation in templates and concepts
 * - Generating `std::variant` or other type-based utilities
 * - Maintaining a single source of truth for supported data types
 *
 * All type lists are expressed as `std::tuple` type aliases to allow compile-time
 * operations like concatenation via `std::tuple_cat`.
 *
 * @copyright Copyright (c) 2025
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>

#include <amon/types/IPAddress.hpp>
#include <amon/types/MACAddress.hpp>
#include <amon/types/Timestamp.hpp>
#include <ipAddress.hpp>

namespace ipxp::process {

// using namespace types;

/**
 * @brief Basic numeric field types.
 *
 * Includes fixed-width unsigned and signed integers as well as floating-point types.
 */
using NumericFieldTypes = std::
	tuple<uint8_t, uint16_t, uint32_t, uint64_t, int8_t, int16_t, int32_t, int64_t, float, double>;

/**
 * @brief Application-specific field types.
 *
 * Contains specialized types like Timestamp, IP and MAC addresses.
 */
using CustomFieldTypes = std::tuple<
	amon::types::Timestamp,
	amon::types::IPv4,
	amon::types::IPv6,
	amon::types::MACAddress,
	IPAddressVariant>;

/**
 * @brief Helper alias for compile-time concatenation of multiple `std::tuple` type lists.
 *
 * This alias template is a `std::tuple_cat` type transformer that produces
 * a single `std::tuple` containing all unique types from the input tuples.
 *
 * @tparam Tuples One or more `std::tuple` type lists to concatenate.
 */
template<typename... Tuples>
using tuple_cat_t = decltype(std::tuple_cat(Tuples {}...));

/**
 * @brief Core set of supported field types.
 *
 * Combination of numeric types and application-specific types.
 */
using CommonFieldTypes = tuple_cat_t<NumericFieldTypes, CustomFieldTypes>;

/**
 * @brief Supported scalar field types.
 *
 * Extends the common type list with:
 * - `std::string_view` for efficient, non-owning textual data access.
 */
using SupportedScalarTypes = tuple_cat_t<CommonFieldTypes, std::tuple<std::string_view>>;

/**
 * @brief Supported vector field types.
 *
 * Extends the common type list with:
 * - `std::string` for owning, mutable textual data
 * - `std::byte` for raw binary data
 */
using SupportedVectorTypes = tuple_cat_t<CommonFieldTypes, std::tuple<std::string, std::byte>>;

} // namespace ipxp::process
