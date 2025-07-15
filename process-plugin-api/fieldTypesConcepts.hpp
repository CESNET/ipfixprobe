#pragma once

#include <concepts>
#include <cstdint>
#include <string>
#include <type_traits>

// Helper trait
template<typename T>
inline constexpr bool is_valid_field_type_v = std::same_as<T, uint8_t> || std::same_as<T, uint16_t>
	|| std::same_as<T, uint32_t> || std::same_as<T, uint64_t> || std::same_as<T, int8_t>
	|| std::same_as<T, int16_t> || std::same_as<T, int32_t> || std::same_as<T, int64_t>
	|| std::same_as<T, float> || std::same_as<T, double>;

// Scalars — string is *excluded*
template<typename T>
concept ValidScalarFieldType = is_valid_field_type_v<T>;

// Vectors — string is included as value vector
template<typename T>
concept ValidVectorFieldType = is_valid_field_type_v<T> || std::same_as<T, std::string>;
