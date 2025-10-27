/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Handle representing a single field within a record.
 *
 * This file defines the FieldHandler class which provides an interface
 * for marking a field as available or unavailable in a record and
 * querying its presence status.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process {

/**
 * @brief Represents a handle to a single field within a record.
 *
 * FieldHandler allows checking whether a field is present in a record
 * and provides methods to set or clear its presence flag in the record's `fieldsAvailable`.
 *
 * The class uses template methods to work with any record type that provides
 * a `fieldsAvailable` member with `set()`, `reset()`, and `test()` methods.
 */
class FieldHandler {
public:
	/**
	 * @brief Sets the associated bit in the record to indicate field availability.
	 *
	 * This method modifies the mutable member `fieldsAvailable` of the record even if
	 * the record instance is const. This is safe and intentional, as the presence
	 * information is considered logically mutable.
	 *
	 * @tparam RecordType Type with fieldsAvailable.set() method.
	 * @param record Reference to record (can be const, modifies only mutable member).
	 */
	template<typename RecordType>
	void setAsAvailable(const RecordType& record) const
	{
		static_assert(requires { record.fieldsAvailable.set(std::size_t {}); });
		record.fieldsAvailable.set(m_bitIndex);
	}

	/**
	 * @brief Clears the associated bit in the record to indicate field unavailability.
	 *
	 * This method modifies the mutable member `fieldsAvailable` of the record even if
	 * the record instance is const. This is safe and intentional, as the presence
	 * information is considered logically mutable.
	 *
	 * @tparam RecordType Type with fieldsAvailable.reset() method.
	 * @param record Reference to record (can be const, modifies only mutable member).
	 */
	template<typename RecordType>
	void setAsUnavailable(const RecordType& record) const
	{
		static_assert(requires { record.fieldsAvailable.reset(std::size_t {}); });
		record.fieldsAvailable.reset(m_bitIndex);
	}

	/**
	 * @brief Returns the availability status of the field in the given record.
	 *
	 * @tparam RecordType Type with fieldsAvailable.test() method.
	 * @param record Record to query.
	 * @return True if the field is available in the record.
	 */

	template<typename RecordType>
	[[nodiscard]] bool getStatus(const RecordType& record) const
	{
		static_assert(requires { record.fieldsAvailable.test(std::size_t {}); });
		return record.fieldsAvailable.test(m_bitIndex);
	}

private:
	friend class FieldManager;

	/// Constructor used only by FieldManager to create a valid handler.
	explicit constexpr FieldHandler(std::size_t bitIndex) noexcept
		: m_bitIndex(bitIndex)
	{
	}

	const std::size_t m_bitIndex;
};

} // namespace ipxp::process
