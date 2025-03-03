/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * @brief This file contains the definition of the `BaseGenerators` struct and the
 * `createGenerators` function. The `BaseGenerators` struct provides generator functions for
 * creating instances of derived classes from a base class. This includes support for unique
 * pointers, shared pointers and constructing at pre-allocated memory.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <functional>
#include <memory>
#include <type_traits>

namespace ipxp {

/**
 * @brief Templated struct `BaseGenerators` provides generator functions for creating instances of
 * derived classes from a base class.
 *
 * @tparam Base The base class type.
 * @tparam Args The types of arguments for the generator functions (constructor of the derived
 * class).
 */
template<typename Base, typename... Args>
struct BaseGenerators {
	std::function<std::unique_ptr<Base>(Args...)>
		uniqueGenerator; ///< Generator for unique pointer.
	std::function<std::shared_ptr<Base>(Args...)>
		sharedGenerator; ///< Generator for shared pointer.
	std::function<Base*(void*, Args...)>
		constructAtGenerator; ///< Generator for constructing at pre-allocated memory.
};

/**
 * @brief Creates a set of generator functions for constructing instances of a derived class.
 *
 * This function generates a `BaseGenerators` instance containing three callable functions
 * that create instances of the specified derived type. The generators provide:
 *  - A factory function returning `std::unique_ptr<Derived>`.
 *  - A factory function returning `std::shared_ptr<Derived>`.
 *  - A function for in-place construction using `std::construct_at`.
 *
 * The function ensures at compile-time that `Derived` is a subclass of `Base`. If `Derived`
 * is not nothrow-constructible with `Args...`, the generator functions will not be marked
 * as `noexcept`, meaning they can throw exceptions if the constructor of `Derived` fails.
 *
 * @tparam Base The base class type.
 * @tparam Derived The derived class type (must inherit from `Base`).
 * @tparam Args The types of arguments used to construct `Derived`.
 * @return A `BaseGenerators` instance containing generator functions for creating `Derived`
 * objects.
 */
template<typename Base, typename Derived, typename... Args>
static BaseGenerators<Base, Args...> createGenerators() noexcept
{
	static_assert(std::is_base_of_v<Base, Derived>, "Derived must be a subclass of Base");

	return {
		[](Args... args) noexcept(std::is_nothrow_constructible_v<Derived, Args...>) {
			return std::make_unique<Derived>(std::forward<Args>(args)...);
		},
		[](Args... args) noexcept(std::is_nothrow_constructible_v<Derived, Args...>) {
			return std::make_shared<Derived>(std::forward<Args>(args)...);
		},
		[](void* ptr, Args... args) noexcept(std::is_nothrow_constructible_v<Derived, Args...>) {
			return std::construct_at(static_cast<Derived*>(ptr), std::forward<Args>(args)...);
		}};
}

} // namespace ipxp