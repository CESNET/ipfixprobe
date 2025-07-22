#pragma once

#include "biflowPair.hpp"
#include "fieldAccessor.hpp"
#include "fieldDescription.hpp"
#include "fieldTypesConcepts.hpp"

#include <algorithm>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ipxp {

template<typename Field>
using FieldPair = std::pair<Field, std::string_view>;

template<typename Field>
using BiflowFieldPair = std::pair<FieldPair<Field>, FieldPair<Field>>;

template<typename Field>
using FieldVariant = std::variant<FieldPair<Field>, BiflowFieldPair<Field>>;

template<typename Field>
FieldVariant<Field> makeBiflowPair(FieldPair<Field> field1, FieldPair<Field> field2) {
    return FieldVariant<Field>(BiflowFieldPair<Field>{field1, field2});
}

template<typename Field>
FieldVariant<Field> makeFieldPair(Field field, std::string_view name) {
    return FieldVariant<Field>(FieldPair<Field>{field, name});
}

/**
 * @brief Represents the schema of a flow record, including field definitions and biflow mappings.
 *
 * The FieldSchema class allows registration of scalar and vector fields along with their accessors.
 * It also tracks biflow field relationships (e.g., SRC_PORT ↔ DST_PORT).
 */
class FieldSchema {
public:
	/**
	 * @brief Constructs a schema with a given group name (http, dns, ...).
	 *
	 * @param groupName Name of the logical group this schema belongs to.
	 */
	[[nodiscard]]
	explicit FieldSchema(std::string_view groupName)
		: m_groupName(groupName)
	{
	}

	/**
	 * @brief Adds a scalar field to the schema.
	 *
	 * @tparam T Scalar type satisfying ValidScalarFieldType concept.
	 * @param fieldName Name of the field.
	 * @param direction Direction of the field (Forward, Reverse, etc.).
	 * @param offset Offset used to access the field from a record.
	 *
	 * @throws std::runtime_error if the field already exists.
	 */
	template<ValidScalarFieldType T>
	void addScalarField(std::string_view fieldName, FieldDirection direction, std::size_t offset)
	{
		addField<T>(fieldName, direction, ScalarAccessor<T> {offset});
	}

	/**
	 * @brief Adds a vector field to the schema.
	 *
	 * @tparam T Vector element type satisfying ValidVectorFieldType concept.
	 * @tparam F Callable that returns a vector accessor.
	 * @param fieldName Name of the field.
	 * @param direction Direction of the field (Forward, Reverse, etc.).
	 * @param accessorFunc Function that provides access to the field's vector value.
	 *
	 * @throws std::runtime_error if the field already exists.
	 */
	template<ValidVectorFieldType T, typename F>
	void addVectorField(std::string_view fieldName, FieldDirection direction, F&& accessorFunc)
	{
		addField<T>(fieldName, direction, VectorAccessor<T> {std::forward<F>(accessorFunc)});
	}

	/**
	 * @brief Adds a biflow pair that logically links two directional fields.
	 *
	 * The order of fields does not matter; the pair (A, B) is considered equivalent to (B, A).
	 *
	 * @param forwardFieldName Field name for the forward direction.
	 * @param reverseFieldName Field name for the reverse direction.
	 *
	 * @throws std::runtime_error if the pair already exists.
	 */

	void addBiflowPair(std::string_view forwardFieldName, std::string_view reverseFieldName)
	{
		if (hasBiflowPair(forwardFieldName, reverseFieldName)) {
			throw std::runtime_error(
				"Biflow pair already exists: " + std::string(forwardFieldName) + " - "
				+ std::string(reverseFieldName));
		}

		m_biflowPairs.emplace_back(
			BiflowPair {std::string(forwardFieldName), std::string(reverseFieldName)});
	}

	template<typename Field>
	void addBiflowPairs(const std::vector<FieldVariant<Field>>& pairs)
	{
		for (const FieldVariant<Field>& fieldVariant : pairs) {
			if (std::holds_alternative<BiflowFieldPair<Field>>(fieldVariant)) {
				const auto& [field1, field2] = std::get<BiflowFieldPair<Field>>(fieldVariant);
				addBiflowPair(field1.second, field2.second);
			}
		}
	}

	/**
	 * @brief Returns all registered fields in this schema.
	 *
	 * @return Vector of field descriptions.
	 */
	[[nodiscard]]
	const std::vector<FieldDescription>& getFields() const noexcept
	{
		return m_fields;
	}

	/**
	 * @brief Returns all registered biflow pairs in this schema.
	 *
	 * @return Vector of biflow pairs.
	 */
	[[nodiscard]]
	const std::vector<BiflowPair>& getBiflowPairs() const noexcept
	{
		return m_biflowPairs;
	}

private:
	template<typename T, typename Getter>
	void addField(std::string_view fieldName, FieldDirection direction, Getter&& getter)
	{
		if (hasField(fieldName)) {
			throw std::runtime_error("Duplicate field name: " + std::string(fieldName));
		}

		const FieldDescription fieldDescription = {
			.group = m_groupName,
			.name = std::string(fieldName),
			.direction = direction,
			.getter = std::forward<Getter>(getter),
		};

		m_fields.emplace_back(std::move(fieldDescription));
	}

	[[nodiscard]]
	bool hasField(std::string_view name) const noexcept
	{
		return std::ranges::any_of(m_fields, [&](const auto& f) { return f.name == name; });
	}

	[[nodiscard]]
	bool hasBiflowPair(std::string_view field1, std::string_view field2) const noexcept
	{
		BiflowPair pair {std::string(field1), std::string(field2)};
		return std::ranges::any_of(m_biflowPairs, [&](const auto& f) { return f == pair; });
	}

	std::string m_groupName;
	std::vector<FieldDescription> m_fields;
	std::vector<BiflowPair> m_biflowPairs;
};

} // namespace ipxp