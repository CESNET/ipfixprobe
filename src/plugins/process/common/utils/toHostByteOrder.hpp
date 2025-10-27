/**
 * @file
 * @brief Utility function to convert integral types to host byte order.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <bit>
#include <cstdint>
#include <type_traits>

#include <arpa/inet.h>

namespace ipxp {

template<typename T>
constexpr T toHostByteOrder(T value)
{
	static_assert(std::is_integral_v<T>, "T must be an integral type");
	static_assert(sizeof(T) <= 8, "Unsupported integer size");

	if constexpr (std::endian::native == std::endian::big) {
		return value;
	}

	auto bytes = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
	std::reverse(bytes.begin(), bytes.end());
	return std::bit_cast<T>(bytes);
}

} // namespace ipxp
