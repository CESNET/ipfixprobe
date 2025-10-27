/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Helper templates for working with type tuples, including tuple membership and
 * tuple-to-variant conversion.
 *
 * This header provides meta-programming utilities to:
 * - Check if a type is contained in a std::tuple.
 * - Convert a std::tuple of types into a std::variant of those types.
 * - Wrap a tuple of types into a tuple of template-instantiated types.
 * - Create a variant over such wrapped types.
 *
 * These utilities are useful for generic programming scenarios involving
 * heterogeneous collections of types and type erasure patterns.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <tuple>
#include <type_traits>
#include <variant>

namespace ipxp::process::detail {

/**
 * @brief Trait to check if a type T is present in a std::tuple.
 *
 * Provides a compile-time boolean value indicating presence.
 *
 * @tparam T     Type to check for.
 * @tparam Tuple Tuple type to inspect.
 *
 * @code
 * static_assert(is_in_tuple_v<int, std::tuple<int, float>>); // true
 * static_assert(!is_in_tuple_v<char, std::tuple<int, float>>); // false
 * @endcode
 */
template<typename T, typename Tuple>
struct is_in_tuple;

template<typename T>
struct is_in_tuple<T, std::tuple<>> : std::false_type {};

template<typename T, typename... Types>
struct is_in_tuple<T, std::tuple<Types...>>
	: std::bool_constant<(std::is_same_v<T, Types> || ...)> {};

/// @brief Helper variable template for @ref is_in_tuple.
template<typename T, typename Tuple>
inline constexpr bool is_in_tuple_v = is_in_tuple<T, Tuple>::value;

/**
 * @brief Converts a std::tuple of types into a std::variant of those types.
 *
 * @tparam Tuple Tuple type to convert.
 *
 * @code
 * using T = std::tuple<int, float>;
 * using V = tuple_to_variant_t<T>; // std::variant<int, float>
 * @endcode
 */
template<typename Tuple>
struct tuple_to_variant;

template<typename... Ts>
struct tuple_to_variant<std::tuple<Ts...>> {
	using type = std::variant<Ts...>;
};

/// @brief Alias template for easier usage of tuple_to_variant.
template<typename Tuple>
using tuple_to_variant_t = typename tuple_to_variant<Tuple>::type;

/**
 * @brief Wraps each type in a tuple by a template template parameter.
 *
 * @tparam Accessor Template template parameter to wrap types.
 * @tparam Tuple    Tuple of types to wrap.
 *
 * @code
 * template<typename T> struct Wrapper {};
 * using Wrapped = wrap_accessors_t<Wrapper, std::tuple<int, float>>;
 * // => std::tuple<Wrapper<int>, Wrapper<float>>
 * @endcode
 */
template<template<typename> typename Accessor, typename Tuple>
struct wrap_accessors;

template<template<typename> typename Accessor, typename... Ts>
struct wrap_accessors<Accessor, std::tuple<Ts...>> {
	using type = std::tuple<Accessor<Ts>...>;
};

/// @brief Alias template for easier usage of wrap_accessors.
template<template<typename> typename Accessor, typename Tuple>
using wrap_accessors_t = typename wrap_accessors<Accessor, Tuple>::type;

/**
 * @brief Variant over wrapped types.
 *
 * Combines @ref wrap_accessors_t and @ref tuple_to_variant_t to directly produce
 * a `std::variant` of wrapped types.
 *
 * @tparam Accessor Template template parameter to wrap types.
 * @tparam Tuple    Tuple of types.
 *
 * @code
 * template<typename T> struct Accessor {};
 * using V = variant_of_accessors_t<Accessor, std::tuple<int, float>>;
 * // => std::variant<Accessor<int>, Accessor<float>>
 * @endcode
 */
template<template<typename> typename Accessor, typename Tuple>
using variant_of_accessors_t = tuple_to_variant_t<wrap_accessors_t<Accessor, Tuple>>;

} // namespace ipxp::process::detail
