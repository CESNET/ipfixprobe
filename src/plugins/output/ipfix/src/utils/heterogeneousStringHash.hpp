/**
 * @file heterogeneousStringHash.hpp
 * @brief Utility class to use std::string and std::string_view interchangeably in hash-based
 * containers.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace ipxp::output::ipfix::utils {

/**
 * @class HeterogeneousStringHash
 * @brief A hash functor that allows using std::string and std::string_view interchangeably as keys
 * in hash-based containers.
 */
struct HeterogeneousStringHash {
	using is_transparent = void;

	size_t operator()(std::string_view stringView) const noexcept
	{
		return std::hash<std::string_view> {}(stringView);
	}

	size_t operator()(const std::string& string) const noexcept
	{
		return std::hash<std::string> {}(string);
	}
};

} // namespace ipxp::output::ipfix::utils