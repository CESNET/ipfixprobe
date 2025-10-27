/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Type traits and helpers for FieldGroup, including scalar/vector detection and
 * element type extraction.
 *
 * This header defines compile-time utilities used by FieldGroup to:
 * - Determine if an accessor is scalar or vector.
 * - Extract element type from std::span or scalar type.
 *
 * @note These helpers are intended primarily for use within FieldGroup.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldAccessor.hpp"

#include <span>
#include <type_traits>

namespace ipxp::process {

/**
 * @brief Extracts the element type from a type, removing const/volatile qualifiers.
 *
 * - If the given type is a `std::span<T, Extent>`, the element type is `T` without cv-qualifiers.
 * - Otherwise, the type itself (without cv-qualifiers) is returned.
 *
 * @tparam T Type to extract from.
 */
template<typename T>
struct span_element_type {
	using type = std::remove_cv_t<T>;
};

template<typename T, std::size_t Extent>
struct span_element_type<std::span<T, Extent>> {
	using type = std::remove_cv_t<T>;
};

/**
 * @brief Trait to detect whether a given accessor template is ScalarAccessor.
 *
 * Defaults to `false`; specialized for `ScalarAccessor<T>`.
 *
 * @tparam Accessor Accessor template (e.g., ScalarAccessor or VectorAccessor)
 * @tparam F Type argument to the accessor template
 */
template<template<typename> class Accessor, typename F>
struct is_scalar_accessor : std::false_type {};

template<typename T>
struct is_scalar_accessor<ScalarAccessor, T> : std::true_type {};

/**
 * @brief Trait to detect whether a given accessor template is VectorAccessor.
 *
 * Defaults to `false`; specialized for `VectorAccessor<T>`.
 *
 * @tparam Accessor Accessor template
 * @tparam F Type argument
 */
template<template<typename> class Accessor, typename F>
struct is_vector_accessor : std::false_type {};

template<typename T>
struct is_vector_accessor<VectorAccessor, T> : std::true_type {};

} // namespace ipxp::process
