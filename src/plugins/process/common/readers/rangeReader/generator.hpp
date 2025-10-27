/**
 * @file
 * @brief Provides a generator utility for creating parsing ranges.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <ranges>

namespace ipxp::Generator {

/**
 * @brief Generates a range by repeatedly invoking a provided generator function.
 *
 * This utility function creates a range that continuously calls the given generator function
 * to produce values. The range can be used in conjunction with other range views to control
 * the number of elements generated or to filter the results.
 *
 * @param generator A callable that produces values of type T when invoked.
 * @tparam T The type of values produced by the generator.
 * @return A range that generates values of type T.
 */
constexpr static auto generate(auto generator) noexcept
{
	return std::views::iota(0)
		| std::views::transform([gen = std::move(generator)](int) mutable { return gen(); });
}

} // namespace ipxp::Generator
