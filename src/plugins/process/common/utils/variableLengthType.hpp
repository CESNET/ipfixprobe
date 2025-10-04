/**
 * @file
 * @brief Defines a template struct for variable length types.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @struct VariableLengthType
 * @brief A template struct that holds a value of type `Type` and its associated length.
 *
 * This struct is useful for representing data types where the length of the data can vary,
 * such as strings or byte arrays. The `value` member holds the actual data, while the `length`
 * member indicates the size of the data in bytes.
 *
 * @tparam Type The type of the value being stored (e.g., integers from MQTT or QUIC).
 */
template<typename Type>
struct VariableLengthType {
	Type value;
	uint16_t length;
};

} // namespace ipxp
