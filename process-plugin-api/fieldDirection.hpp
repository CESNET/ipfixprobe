#pragma once

#include <cstdint>
#include <stdexcept>

namespace ipxp {

	/**
 * @brief Enum representing the direction of a flow field.
 *
 * FieldDirection enum is used to represent the possible directions for a field.
 * It supports single directions (Forward, Reverse), combined direction (Biflow),
 * and an indifferent direction (DirectionalIndifferent).
 */
enum class FieldDirection : uint8_t {
	DirectionalIndifferent = 0, ///< No specific direction.
	Forward = 1, ///< Represents forward direction.
	Reverse = 2, ///< Represents reverse direction.
	Biflow = Forward | Reverse ///< Combination of both forward and reverse directions.
};

/**
 * @brief Helper function to check if a FieldDirection contains the Forward direction.
 *
 * @param dir The FieldDirection to check.
 * @return true If the FieldDirection includes Forward.
 * @return false Otherwise.
 */
inline bool hasForward(FieldDirection dir)
{
	return static_cast<uint8_t>(dir) & static_cast<uint8_t>(FieldDirection::Forward);
}

/**
 * @brief Helper function to check if a FieldDirection contains the Reverse direction.
 *
 * @param dir The FieldDirection to check.
 * @return true If the FieldDirection includes Reverse.
 * @return false Otherwise.
 */
inline bool hasReverse(FieldDirection dir)
{
	return static_cast<uint8_t>(dir) & static_cast<uint8_t>(FieldDirection::Reverse);
}

/**
 * @brief Helper function to check if a FieldDirection is indifferent (does not specify any
 * direction).
 *
 * @param dir The FieldDirection to check.
 * @return true If the FieldDirection is DirectionalIndifferent.
 * @return false Otherwise.
 */
inline bool isIndifferent(FieldDirection dir)
{
	return dir == FieldDirection::DirectionalIndifferent;
}

/**
 * @brief Helper function to check if a FieldDirection represents Biflow (both Forward and Reverse).
 *
 * @param dir The FieldDirection to check.
 * @return true If the FieldDirection is Biflow.
 * @return false Otherwise.
 */
inline bool isBiflow(FieldDirection dir)
{
	return dir == FieldDirection::Biflow;
}

/**
 * @brief Converts a FieldDirection to a human-readable string.
 *
 * @param dir The FieldDirection to convert.
 * @return A string representation of the FieldDirection.
 */
inline const char* toString(FieldDirection dir)
{
	switch (dir) {
	case FieldDirection::DirectionalIndifferent:
		return "DirectionalIndifferent";
	case FieldDirection::Forward:
		return "Forward";
	case FieldDirection::Reverse:
		return "Reverse";
	case FieldDirection::Biflow:
		return "Biflow";
	default:
		throw std::invalid_argument("Unknown FieldDirection value.");
	}
}

} // namespace ipxp