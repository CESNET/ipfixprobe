#pragma once

#include "fieldAccessor.hpp"
#include "fieldDescription.hpp"
#include "flowRecord.hpp"

namespace ipxp {

/**
 * @brief Represents a resolved output field that can be queried from a FlowRecord.
 *
 * This class wraps a field description and provides methods to access its metadata
 * (name, group, direction, getter) as well as check if the field is present
 * in a specific FlowRecord instance.
 */
class OutputField {
public:
	/**
	 * @brief Returns the name of the field.
	 * @return Field name as string_view.
	 */
	[[nodiscard]]
	std::string_view getName() const noexcept
	{
		return m_field.name;
	}

	/**
	 * @brief Returns the logical group name of the field.
	 * @return Group name (e.g., "tcp", "http").
	 */
	[[nodiscard]]
	std::string_view getGroup() const noexcept
	{
		return m_field.group;
	}

	/**
	 * @brief Returns the direction of the field.
	 * @return Direction enum (Forward, Reverse, Indifferent).
	 */
	[[nodiscard]]
	FieldDirection getDirection() const noexcept
	{
		return m_field.direction;
	}

	/**
	 * @brief Returns the generic value accessor for the field.
	 * @return Reference to GenericValueGetter variant.
	 */
	[[nodiscard]]
	const GenericValueGetter& getValueGetter() const noexcept
	{
		return m_field.getter;
	}

	/**
	 * @brief Checks whether this field is present in a given FlowRecord.
	 * @param record Flow record to query.
	 * @return True if the field is available in the record.
	 */
	[[nodiscard]]
	bool isInRecord(const FlowRecord& record) const
	{
		return record.fieldsAvailable.test(m_bitIndex);
	}

private:
	friend class FieldManager;

	/**
	 * @brief Constructs an OutputField with associated metadata and bit index.
	 * @param fieldDescription Field metadata including name, direction, accessor.
	 * @param fieldBitIndex Index into FlowRecord::fieldsAvailable.
	 */
	OutputField(FieldDescription fieldDescription, std::size_t fieldBitIndex)
		: m_field(std::move(fieldDescription))
		, m_bitIndex(fieldBitIndex)
	{
	}

	/// Field metadata.
	const FieldDescription m_field;

	/// Bit index used to check presence in FlowRecord.
	const std::size_t m_bitIndex;
};

} // namespace ipxp