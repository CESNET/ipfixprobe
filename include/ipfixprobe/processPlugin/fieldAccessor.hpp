/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Accessor templates for scalar and vector fields with type-safe getters.
 *
 * This header defines the `ScalarAccessor` and `VectorAccessor` templates, which provide
 * a type-safe and performant way to access scalar and vector field values from external
 * data structures using function pointers.
 *
 * These accessors encapsulate a getter function pointer to retrieve the value from
 * a void pointer to the external data, ensuring compile-time type safety via concepts.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldTypeConcepts.hpp"

#include <cassert>
#include <span>

namespace ipxp {

/**
 * @brief Accessor for scalar values.
 *
 * Provides a mechanism to access a scalar value of type `T` from an external data
 * structure via a getter function pointer.
 *
 * @tparam T Type of scalar value (must satisfy `FlowDataTypeScalar ` concept).
 */
template<FlowDataTypeScalar T>
class ScalarAccessor {
public:
	/// Function pointer type returning a scalar value of type T from a data pointer.
	using GetterFunction = T (*)(const void*);

	/**
	 * @brief Constructs the ScalarAccessor with a getter function.
	 *
	 * @param getterFunction Function pointer used to extract the scalar value.
	 *
	 * @note The getter function pointer must not be null.
	 */
	explicit constexpr ScalarAccessor(GetterFunction getterFunction)
		: m_getterFunction(getterFunction)
	{
		assert(m_getterFunction && "ScalarAccessor: getter function must not be nullptr");
	}

	/**
	 * @brief Retrieves the scalar value by invoking the getter function.
	 *
	 * @param data Pointer to the external data structure.
	 * @return Extracted scalar value of type T.
	 */
	[[nodiscard]] T operator()(const void* data) const { return m_getterFunction(data); }

	ScalarAccessor() = delete;
	ScalarAccessor(const ScalarAccessor&) = default;
	ScalarAccessor& operator=(const ScalarAccessor&) = default;
	ScalarAccessor(ScalarAccessor&&) = default;
	ScalarAccessor& operator=(ScalarAccessor&&) = default;

private:
	const GetterFunction m_getterFunction;
};

/**
 * @brief Accessor for vector values.
 *
 * Provides a mechanism to access a span of values of type `T` from an external data
 * structure via a getter function pointer.
 *
 * @tparam T Type of vector element (must satisfy `FlowDataTypeVector` concept).
 */
template<FlowDataTypeVector T>
class VectorAccessor {
public:
	/// Function pointer type returning a span of constant values of type T from a data pointer.
	using GetterFunction = std::span<const T> (*)(const void*);

	/**
	 * @brief Constructs the VectorAccessor with a getter function.
	 *
	 * @param getterFunction Function pointer used to extract the vector span.
	 *
	 * @note The getter function pointer must not be null.
	 */
	explicit constexpr VectorAccessor(GetterFunction getterFunction)
		: m_getterFunction(getterFunction)
	{
		assert(m_getterFunction && "VectorAccessor: getter function must not be nullptr");
	}

	/**
	 * @brief Retrieves the vector span by invoking the getter function.
	 *
	 * @param data Pointer to the external data structure.
	 * @return Extracted span of constant values of type T.
	 */
	[[nodiscard]] std::span<const T> operator()(const void* data) const
	{
		return m_getterFunction(data);
	}

	VectorAccessor() = delete;
	VectorAccessor(const VectorAccessor&) = default;
	VectorAccessor& operator=(const VectorAccessor&) = default;
	VectorAccessor(VectorAccessor&&) = default;
	VectorAccessor& operator=(VectorAccessor&&) = default;

private:
	const GetterFunction m_getterFunction;
};

} // namespace ipxp
