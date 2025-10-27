/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Type-erased variants for scalar and vector field accessors.
 *
 * Defines `ScalarValueGetter`, `VectorValueGetter`, and `GenericValueGetter` as `std::variant`
 * types that hold accessors for all supported scalar and vector field types.
 *
 * These variants allow uniform storage and usage of heterogeneous field accessors
 * without template overhead, enabling runtime polymorphism without virtual functions.
 *
 * @see ScalarAccessor
 * @see VectorAccessor
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldAccessor.hpp"
#include "fieldSupportedTypes.hpp"
#include "typeUtils.hpp"

namespace ipxp {

/**
 * @brief Variant holding any scalar field accessor for supported scalar types.
 */
using ScalarValueGetter = detail::variant_of_accessors_t<ScalarAccessor, SupportedScalarTypes>;

/**
 * @brief Variant holding any vector field accessor for supported vector types.
 */
using VectorValueGetter = detail::variant_of_accessors_t<VectorAccessor, SupportedVectorTypes>;

/**
 * @brief Variant holding either a scalar or a vector field accessor.
 *
 * Allows storing any supported accessor type in a single variable,
 * simplifying generic code paths.
 */
using GenericValueGetter = std::variant<ScalarValueGetter, VectorValueGetter>;

} // namespace ipxp
