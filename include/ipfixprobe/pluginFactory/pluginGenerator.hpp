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
 * @brief Creates a set of generators for a specific derived type.
 *
 * This function creates a `BaseGenerators` instance populated with generator functions that can
 * create instances of the specified derived type. It uses static assertions to ensure that the
 * derived type is a subclass of the base type.
 *
 * @tparam Base The base class type.
 * @tparam Derived The derived class type.
 * @tparam Args The types of arguments for the generator functions.
 * @return A `BaseGenerators` instance with generator functions for the specified derived type.
 *
 * @throw std::invalid_argument If `Derived` is not a subclass of `Base`.
 */
/*
template<typename Base, typename Derived, typename... Args>
static BaseGenerators<Base, Args...> createGenerators() noexcept
{
        static_assert(std::is_base_of_v<Base, Derived>, "Derived must be a subclass of Base");

        BaseGenerators<Base, Args...> generators = {};

        generators.uniqueGenerator
                = [](Args... args) { return std::make_unique<Derived>(std::forward<Args>(args)...);
};

        generators.sharedGenerator
                = [](Args... args) { return std::make_shared<Derived>(std::forward<Args>(args)...);
};

        generators.constructAtGenerator = [](void* ptr, Args... args) {
                return std::construct_at(static_cast<Derived*>(ptr), std::forward<Args>(args)...);
        };

        return generators;
}
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
