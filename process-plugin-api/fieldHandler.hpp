#pragma once

#include "flowRecord.hpp"

#include <cstdint>
#include <limits>
#include <stdexcept>

/**
 * @brief Represents a handle to a single field within a FlowRecord.
 *
 * FieldHandler allows checking whether a field is present in a record
 * and provides methods to set or clear its presence flag in `FlowRecord::fieldsAvailable`.
 *
 * The handler must be initialized (via FieldManager) with a valid bit index before use.
 */
class FieldHandler {
public:
	/**
	 * @brief Default constructor creates an uninitialized handler.
	 */
	FieldHandler() noexcept
		: m_bitIndex(s_invalidIndex)
	{
	}

	/**
	 * @brief Sets the associated bit in the FlowRecord to indicate field availability.
	 * @throws std::logic_error if the handler is uninitialized.
	 */
	void setAsAvailable(FlowRecord& record)
	{
		checkInitialized();
		record.fieldsAvailable.set(m_bitIndex);
	}

	/**
	 * @brief Clears the associated bit in the FlowRecord to indicate field unavailability.
	 * @throws std::logic_error if the handler is uninitialized.
	 */
	void setAsUnavailable(FlowRecord& record)
	{
		checkInitialized();
		record.fieldsAvailable.reset(m_bitIndex);
	}

	/**
	 * @brief Returns the availability status of the field in the given FlowRecord.
	 * @throws std::logic_error if the handler is uninitialized.
	 */
	[[nodiscard]]
	bool getStatus(const FlowRecord& record) const
	{
		checkInitialized();
		return record.fieldsAvailable.test(m_bitIndex);
	}

	/// Returns the bit index associated with this field.
	[[nodiscard]]
	std::size_t getIndex() const noexcept
	{
		return m_bitIndex;
	}

	/// Returns true if the handler is associated with a valid field.
	[[nodiscard]]
	bool isInitialized() const noexcept
	{
		return m_bitIndex != s_invalidIndex;
	}

private:
	friend class FieldManager;

	/// Constructor used only by FieldManager to create a valid handler.
	explicit FieldHandler(std::size_t bitIndex) noexcept
		: m_bitIndex(bitIndex)
	{
	}

	/// Throws std::logic_error if the handler is uninitialized.
	void checkInitialized() const
	{
		if (!isInitialized()) [[unlikely]] {
			throw std::logic_error("FieldHandler is not initialized");
		}
	}

	/// Special value used to mark an uninitialized handler.
	static constexpr std::size_t s_invalidIndex = std::numeric_limits<std::size_t>::max();
	std::size_t m_bitIndex;
};
