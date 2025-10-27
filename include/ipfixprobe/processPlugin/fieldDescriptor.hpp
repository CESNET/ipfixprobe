/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Lukas Hutak <hutak@cesnet.cz>
 * @brief Provides the FieldDescriptor class for accessing field metadata and value getters.
 *
 * This class encapsulates information about a field in a FlowRecord, including its
 * name, group, bit index, and a generic value accessor. It allows checking if the
 * field is present in a specific FlowRecord. Construction is restricted to FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldGenericValueGetter.hpp"
#include "fieldInfo.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace ipxp::process {

/**
 * @class FieldDescriptor
 * @brief Read-only access to field metadata and value getters.
 *
 * FieldDescriptor represents a single field within a FlowRecord. It provides
 * information about the field's name, logical group, bit index, and a generic
 * value accessor. It allows checking if the field is present in a specific
 * FlowRecord using the `isInRecord()` method.
 *
 * Instances are immutable and can only be created by FieldManager, ensuring
 * controlled registration and consistent state of fields.
 */
class FieldDescriptor {
public:
	/**
	 * @brief Returns the name of the field.
	 * @return Field name as string_view.
	 */
	[[nodiscard]]
	std::string_view getName() const noexcept
	{
		return m_fieldInfo.name;
	}

	/**
	 * @brief Returns the logical group name of the field.
	 * @return Group name (e.g., "tcp", "http").
	 */
	[[nodiscard]]
	std::string_view getGroup() const noexcept
	{
		return m_fieldInfo.group;
	}

	/**
	 * @brief Returns the generic value accessor for the field.
	 * @return Reference to GenericValueGetter variant.
	 */
	[[nodiscard]]
	const GenericValueGetter& getValueGetter() const noexcept
	{
		return m_fieldInfo.getter;
	}

	/**
	 * @brief Returns the bit index used to check field presence in FlowRecord.
	 * @return Bit index as size_t.
	 */
	[[nodiscard]]
	std::size_t getBitIndex() const noexcept
	{
		return m_fieldInfo.bitIndex;
	}

	/**
	 * @brief Checks whether this field is present in a given record.
	 * @tparam RecordType Type with fieldsAvailable.test() method.
	 * @param record Record to query.
	 * @return True if the field is available in the record.
	 */
	template<typename RecordType>
	[[nodiscard]]
	bool isInRecord(const RecordType& record) const
	{
		static_assert(
			requires { record.fieldsAvailable.test(std::size_t {}); },
			"RecordType must have fieldsAvailable.test() method");

		return record.fieldsAvailable.test(m_fieldInfo.bitIndex);
	}

private:
	// FieldDescriptor can only be constructed by FieldManager
	friend class FieldManager;

	explicit FieldDescriptor(FieldInfo fieldInfo)
		: m_fieldInfo(std::move(fieldInfo))
	{
	}

	const FieldInfo m_fieldInfo;
};

} // namespace ipxp::process
