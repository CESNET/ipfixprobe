#pragma once

#include <string>
#include <utility>

/**
 * @brief Represents a pair of field names that are semantically linked in a bidirectional flow.
 *
 * The order of the fields does not matter; (A, B) is considered equal to (B, A).
 */
struct BiflowPair {
	std::string forwardField; ///< Field name representing the forward direction.
	std::string reverseField; ///< Field name representing the reverse direction.

	/**
	 * @brief Constructs a BiflowPair with the given field names.
	 *
	 * @param forward Name of the forward-direction field.
	 * @param reverse Name of the reverse-direction field.
	 */
	BiflowPair(std::string forward, std::string reverse)
		: forwardField(std::move(forward))
		, reverseField(std::move(reverse))
	{
	}

	/**
	 * @brief Compares two BiflowPairs for equality.
	 *
	 * The comparison is order-independent: (A, B) == (B, A).
	 *
	 * @param other The BiflowPair to compare with.
	 * @return true if the pairs are semantically equal.
	 */
	bool operator==(const BiflowPair& other) const
	{
		return (forwardField == other.forwardField && reverseField == other.reverseField)
			|| (forwardField == other.reverseField && reverseField == other.forwardField);
	}

	/**
	 * @brief Compares two BiflowPairs for inequality.
	 *
	 * @param other The BiflowPair to compare with.
	 * @return true if the pairs are not equal.
	 */
	bool operator!=(const BiflowPair& other) const { return !(*this == other); }
};
