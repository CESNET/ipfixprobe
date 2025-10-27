/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Concepts for validating supported scalar and vector field types.
 *
 * This header defines C++20 concepts that check whether a type is a valid
 * scalar or vector field type, based on predefined type lists.
 *
 * It relies on tuple membership traits defined in the detail namespace.
 *
 * @see fieldSupportedTypes.hpp
 * @see tupleUtils.hpp
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldSupportedTypes.hpp"
#include "typeUtils.hpp"

namespace ipxp {

/**
 * @brief Concept checking if a type T is a valid scalar field type.
 *
 * Valid scalar field types are those contained in the SupportedScalarTypes tuple.
 *
 * @tparam T Type to check.
 */
template<typename T>
concept FlowDataTypeScalar = detail::is_in_tuple_v<T, SupportedScalarTypes>;

/**
 * @brief Concept checking if a type T is a valid vector field type.
 *
 * Valid vector field types are those contained in the SupportedVectorTypes tuple.
 *
 * @tparam T Type to check.
 */
template<typename T>
concept FlowDataTypeVector = detail::is_in_tuple_v<T, SupportedVectorTypes>;

} // namespace ipxp
