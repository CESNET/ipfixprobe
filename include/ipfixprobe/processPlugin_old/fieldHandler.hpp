/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Handle representing a single field within a FlowRecord.
 *
 * This file defines the FieldHandler class which provides an interface
 * for marking a field as available or unavailable in a FlowRecord and
 * querying its presence status.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "flowRecord.hpp"

#include <cstdint>

namespace ipxp {

/**
 * @brief Represents a handle to a single field within a FlowRecord.
 *
 * FieldHandler allows checking whether a field is present in a record
 * and provides methods to set or clear its presence flag in `FlowRecord::fieldsAvailable`.
 */
class FieldHandler {
public:
	/**
	 * @brief Sets the associated bit in the FlowRecord to indicate field availability.
	 *
	 * This method modifies the mutable member `fieldsAvailable` of FlowRecord even if
	 * the FlowRecord instance is const. This is safe and intentional, as the presence
	 * information is considered logically mutable.
	 *
	 * @param record Reference to FlowRecord (can be const, modifies only mutable member).
	 */
	void setAsAvailable(const FlowRecord& record) const { record.fieldsAvailable.set(m_bitIndex); }

	/**
	 * @brief Clears the associated bit in the FlowRecord to indicate field unavailability.
	 *
	 * This method modifies the mutable member `fieldsAvailable` of FlowRecord even if
	 * the FlowRecord instance is const. This is safe and intentional, as the presence
	 * information is considered logically mutable.
	 *
	 * @param record Reference to FlowRecord (can be const, modifies only mutable member).
	 */
	void setAsUnavailable(const FlowRecord& record) const
	{
		record.fieldsAvailable.reset(m_bitIndex);
	}

	/**
	 * @brief Returns the availability status of the field in the given FlowRecord.
	 */
	[[nodiscard]]
	bool getStatus(const FlowRecord& record) const
	{
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

} // namespace ipxp
