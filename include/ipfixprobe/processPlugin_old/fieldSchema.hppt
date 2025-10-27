/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Provides the FieldSchema class for registering scalar, vector, directional, and biflow
 * fields.
 *
 * FieldSchema is responsible for managing field metadata within a specific group.
 * It allows adding scalar and vector fields, as well as pairs of fields that
 * represent either directional or biflow traffic. The class interfaces with
 * FieldManager to register fields and maintain consistency in FlowRecords.
 *
 * The template methods enable flexible accessor functions for fields, supporting:
 * - Scalar values
 * - Vector values (std::span)
 * - Directional field pairs (forward/reverse)
 * - Biflow field pairs (A/B)
 *
 * @note FieldSchema instances are constructed by FieldManager and are tied to
 *       a specific field group.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldHandler.hpp"
#include "fieldManager.hpp"
#include "fieldSchemaTypeTraits.hpp"

#include <cstdint>
#include <string_view>
#include <type_traits>
#include <utility>

namespace ipxp {

/**
 * @class FieldSchema
 * @brief Manages registration of scalar, vector, directional, and biflow fields.
 *
 * This class acts as a bridge between user-provided accessor functions and the FieldManager,
 * ensuring type consistency and correct registration.
 *
 * ## Example: Adding a scalar field
 * @code
 * FieldSchema schema = fieldManager.createFieldSchema("my_group");
 *
 * schema.addScalarField("packet_count", [](const void* rec) {
 *     return static_cast<const MyRecord*>(rec)->pktCount;
 * });
 * @endcode
 *
 * ## Example: Adding a vector field
 * @code
 * schema.addVectorField("payload", [](const void* rec) {
 *     auto r = static_cast<const MyRecord*>(rec);
 *     return std::span<const uint8_t>(r->payload, r->payloadLength);
 * });
 * @endcode
 *
 * ## Example: Adding a directional pair of scalar fields
 * @code
 * schema.addScalarDirectionalFields(
 *     "fwd_packets", "rev_packets",
 *     [](const void* rec) { return static_cast<const MyRecord*>(rec)->fwdCount; },
 *     [](const void* rec) { return static_cast<const MyRecord*>(rec)->revCount; }
 * );
 * @endcode
 */
class FieldSchema {
public:
	/**
	 * @brief Registers a scalar field.
	 *
	 * @tparam AccessorFunction Callable returning the field value.
	 * @param fieldName Name of the field.
	 * @param accessorFunction Function that retrieves the field value.
	 * @return FieldHandler Handle to the registered field.
	 */
	template<typename AccessorFunction>
	[[nodiscard]] FieldHandler
	addScalarField(std::string_view fieldName, AccessorFunction&& accessorFunction)
	{
		return addFieldGeneric<ScalarAccessor>(
			fieldName,
			std::forward<AccessorFunction>(accessorFunction));
	}

	/**
	 * @brief Registers a vector field.
	 *
	 * @tparam AccessorFunction Callable returning a `std::span` of values.
	 * @param fieldName Name of the field.
	 * @param accessorFunction Function that retrieves the field values.
	 * @return FieldHandler Handle to the registered field.
	 */
	template<typename AccessorFunction>
	[[nodiscard]] FieldHandler
	addVectorField(std::string_view fieldName, AccessorFunction&& accessorFunction)
	{
		return addFieldGeneric<VectorAccessor>(
			fieldName,
			std::forward<AccessorFunction>(accessorFunction));
	}

	/**
	 * @brief Registers a pair of scalar fields representing directional traffic.
	 *
	 * @tparam ForwardAccessorFunction Accessor for the forward direction.
	 * @tparam ReverseAccessorFunction Accessor for the reverse direction.
	 * @param forwardFieldName Name of the forward field.
	 * @param reverseFieldName Name of the reverse field.
	 * @param forwardAccessorFunction Getter for the forward value.
	 * @param reverseAccessorFunction Getter for the reverse value.
	 * @return Pair of FieldHandler objects for forward and reverse fields.
	 */
	template<typename ForwardAccessorFunction, typename ReverseAccessorFunction>
	[[nodiscard]] std::pair<FieldHandler, FieldHandler> addScalarDirectionalFields(
		std::string_view forwardFieldName,
		std::string_view reverseFieldName,
		ForwardAccessorFunction&& forwardAccessorFunction,
		ReverseAccessorFunction&& reverseAccessorFunction)
	{
		return addPairFieldsGeneric<ScalarAccessor>(
			forwardFieldName,
			reverseFieldName,
			std::forward<ForwardAccessorFunction>(forwardAccessorFunction),
			std::forward<ReverseAccessorFunction>(reverseAccessorFunction),
			PairType::Directional);
	}

	/**
	 * @brief Registers a pair of vector fields representing directional traffic.
	 *
	 * @tparam ForwardAccessorFunction Accessor for the forward direction.
	 * @tparam ReverseAccessorFunction Accessor for the reverse direction.
	 * @param forwardFieldName Name of the forward field.
	 * @param reverseFieldName Name of the reverse field.
	 * @param forwardAccessorFunction Getter for the forward value.
	 * @param reverseAccessorFunction Getter for the reverse value.
	 * @return Pair of FieldHandler objects for forward and reverse fields.
	 */
	template<typename ForwardAccessorFunction, typename ReverseAccessorFunction>
	[[nodiscard]] std::pair<FieldHandler, FieldHandler> addVectorDirectionalFields(
		std::string_view forwardFieldName,
		std::string_view reverseFieldName,
		ForwardAccessorFunction&& forwardAccessorFunction,
		ReverseAccessorFunction&& reverseAccessorFunction)
	{
		return addPairFieldsGeneric<VectorAccessor>(
			forwardFieldName,
			reverseFieldName,
			std::forward<ForwardAccessorFunction>(forwardAccessorFunction),
			std::forward<ReverseAccessorFunction>(reverseAccessorFunction),
			PairType::Directional);
	}

	/**
	 * @brief Registers a pair of scalar fields representing biflow traffic.
	 *
	 * @param aFieldName Name of the "A" field.
	 * @param bFieldName Name of the "B" field.
	 * @param aGetter Getter for the "A" value.
	 * @param bGetter Getter for the "B" value.
	 */
	template<typename ForwardAccessorFunction, typename ReverseAccessorFunction>
	[[nodiscard]] std::pair<FieldHandler, FieldHandler> addScalarBiflowFields(
		std::string_view aFieldName,
		std::string_view bFieldName,
		ForwardAccessorFunction&& aGetter,
		ReverseAccessorFunction&& bGetter)
	{
		return addPairFieldsGeneric<ScalarAccessor>(
			aFieldName,
			bFieldName,
			std::forward<ForwardAccessorFunction>(aGetter),
			std::forward<ReverseAccessorFunction>(bGetter),
			PairType::Biflow);
	}

	/**
	 * @brief Registers a pair of vector fields representing biflow traffic.
	 *
	 * @param aFieldName Name of the "A" field.
	 * @param bFieldName Name of the "B" field.
	 * @param aGetter Getter for the "A" value.
	 * @param bGetter Getter for the "B" value.
	 */
	template<typename ForwardAccessorFunction, typename ReverseAccessorFunction>
	[[nodiscard]] std::pair<FieldHandler, FieldHandler> addVectorBiflowFields(
		std::string_view aFieldName,
		std::string_view bFieldName,
		ForwardAccessorFunction&& aGetter,
		ReverseAccessorFunction&& bGetter)
	{
		return addPairFieldsGeneric<VectorAccessor>(
			aFieldName,
			bFieldName,
			std::forward<ForwardAccessorFunction>(aGetter),
			std::forward<ReverseAccessorFunction>(bGetter),
			PairType::Biflow);
	}

private:
	template<typename AccessorFunction>
	using FieldType = std::invoke_result_t<AccessorFunction, const void*>;

	template<typename AccessorFunction>
	using ElementType = typename span_element_type<FieldType<AccessorFunction>>::type;

	enum class PairType : uint8_t {
		Directional,
		Biflow,
	};

	// Can be constructed only by FieldManager
	friend class FieldManager;

	FieldSchema(std::string_view groupName, FieldManager& manager)
		: m_groupName(std::string(groupName))
		, m_fieldManager(manager)
	{
	}

	template<template<typename> class Accessor, typename AccessorFunction>
	[[nodiscard]] FieldHandler
	addFieldGeneric(std::string_view fieldName, AccessorFunction&& accessorFunction)
	{
		using T = FieldType<AccessorFunction>;
		return m_fieldManager.registerField(
			m_groupName,
			fieldName,
			Accessor<T> {std::forward<AccessorFunction>(accessorFunction)});
	}

	// T
	template<
		template<typename> class Accessor,
		typename ForwardAccessorFunction,
		typename ReverseAccessorFunction>
	[[nodiscard]] std::pair<FieldHandler, FieldHandler> addPairFieldsGeneric(
		std::string_view fieldNameA,
		std::string_view fieldNameB,
		ForwardAccessorFunction&& forwardAccessorFunction,
		ReverseAccessorFunction&& reverseAccessorFunctionB,
		PairType pairType)
	{
		using TaRaw = FieldType<ForwardAccessorFunction>;
		using TbRaw = FieldType<ReverseAccessorFunction>;

		static_assert(
			std::is_same_v<TaRaw, TbRaw>,
			"Accessor functions for pair fields must return the same type");

		using Ta = std::conditional_t<
			is_scalar_accessor<Accessor, FieldType<ForwardAccessorFunction>>::value,
			TaRaw,
			ElementType<ForwardAccessorFunction>>;

		using Tb = std::conditional_t<
			is_scalar_accessor<Accessor, FieldType<ReverseAccessorFunction>>::value,
			TbRaw,
			ElementType<ReverseAccessorFunction>>;

		const Accessor<Ta> accessorA {
			std::forward<ForwardAccessorFunction>(forwardAccessorFunction)};
		const Accessor<Tb> accessorB {
			std::forward<ReverseAccessorFunction>(reverseAccessorFunctionB)};

		switch (pairType) {
		case PairType::Biflow:
			return m_fieldManager.registerBiflowPairFields(
				m_groupName,
				fieldNameA,
				fieldNameB,
				std::move(accessorA),
				std::move(accessorB));
		case PairType::Directional:
			return m_fieldManager.registerDirectionalPairFields(
				m_groupName,
				fieldNameA,
				fieldNameB,
				std::move(accessorA),
				std::move(accessorB));
		}

		__builtin_unreachable();
	}

	std::string m_groupName;
	FieldManager& m_fieldManager;
};

} // namespace ipxp
