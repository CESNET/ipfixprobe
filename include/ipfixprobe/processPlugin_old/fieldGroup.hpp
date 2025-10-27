/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Provides the FieldGroup class for registering scalar, vector, directional, and biflow
 * fields.
 *
 * FieldGroup is responsible for managing field metadata within a specific group.
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
 * @note FieldGroup instances are constructed by FieldManager and are tied to
 *       a specific field group.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldGroupTypeTraits.hpp"
#include "fieldHandler.hpp"
#include "fieldManager.hpp"

#include <cstdint>
#include <string_view>
#include <type_traits>
#include <utility>

namespace ipxp {

/**
 * @class FieldGroup
 * @brief Manages registration of scalar, vector, directional, and biflow fields.
 *
 * FieldGroup acts as a bridge between user-provided accessor functions and the FieldManager,
 * ensuring type consistency and correct registration of fields.
 *
 * It supports the following types of fields:
 * - Scalar values
 * - Vector values (`std::span`)
 * - Directional field pairs (forward/reverse)
 * - Biflow field pairs (A/B)
 *
 * ### Directional Pairs
 *
 * DirectionalPair is used for fields that have a forward and a reverse component.
 * Typical example: `packets` (forward) and `packets_rev` (reverse).
 *
 * Behavior depends on flow view:
 *
 * | Flow Type        | Forward Field       | Reverse Field       |
 * |------------------|---------------------|---------------------|
 * | Forward Uniflow  | exported            | ignored             |
 * | Reverse Uniflow  | ignored             | exported as forward |
 * | Biflow           | exported            | exported            |
 * | Reverse Biflow   | exported as reverse | exported as forward |
 *
 * This ensures consistent handling of directional metrics across different flow representations.
 *
 * ### Biflow Pairs
 *
 * BiflowPair is used for fields that conceptually belong to two sides of a bidirectional flow.
 * Typical example: `src_port` (A) and `dst_port` (B).
 * Behavior depends on flow view:
 *
 * | Flow Type        | A Field         | B Field         |
 * |------------------|-----------------|-----------------|
 * | Forward Uniflow  | exported        | exported        |
 * | Reverse Uniflow  | exported as B   | exported as A   |
 * | Biflow           | exported        | exported        |
 * | Reverse Biflow   | exported as B   | exported as A   |
 *
 *
 * ## Example: Adding a scalar field
 * @code
 * FieldGroup group = fieldManager.createFieldGroup("my_group");
 *
 * group.addScalarField("packet_count", [](const void* rec) {
 *     return reinterpret_cast<const MyRecord*>(rec)->pktCount;
 * });
 * @endcode
 *
 * ## Example: Adding a vector field
 * @code
 * group.addVectorField("payload", [](const void* rec) {
 *     auto r = reinterpret_cast<const MyRecord*>(rec);
 *     return std::span<const uint8_t>(r->payload, r->payloadLength);
 * });
 * @endcode
 *
 * ## Example: Adding a directional pair of scalar fields
 * @code
 * group.addScalarDirectionalFields(
 *     "fwd_packets", "rev_packets",
 *     [](const void* rec) { return reinterpret_cast<const MyRecord*>(rec)->fwdCount; },
 *     [](const void* rec) { return reinterpret_cast<const MyRecord*>(rec)->revCount; }
 * );
 * @endcode
 */
class FieldGroup {
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
	 * @note This registers a **DirectionalPair**, see class documentation for behavior.
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
	 * @note This registers a **DirectionalPair**, see class documentation for behavior.
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
	 * @note This registers a **BiflowPair**, see class documentation for behavior.
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
	 * @note This registers a **BiflowPair**, see class documentation for behavior.
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

	FieldGroup(std::string_view groupName, FieldManager& manager)
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

		throw std::logic_error("Unreachable code in addPairFieldsGeneric");
	}

	std::string m_groupName;
	FieldManager& m_fieldManager;
};

} // namespace ipxp
