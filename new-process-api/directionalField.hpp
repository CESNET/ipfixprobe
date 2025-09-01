#pragma once

#include <cstdint>

enum Direction : std::size_t { Forward = 0, Reverse = 1 };

template<typename T>
struct DirectionalField {
	T values[2]{};

	constexpr T& operator[](Direction d) { return values[static_cast<std::size_t>(d)]; }
	constexpr const T& operator[](Direction d) const { return values[static_cast<std::size_t>(d)]; }
};