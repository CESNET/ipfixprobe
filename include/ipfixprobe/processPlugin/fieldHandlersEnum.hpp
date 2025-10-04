#pragma once

#include "fieldHandler.hpp"

#include <boost/container/static_vector.hpp>

namespace ipxp {

/**
 * @brief Helper to determine the number of enum values.
 *
 * Requires that the enum defines a final enumerator named `FIELDS_SIZE`.
 *
 * @tparam E The enum type.
 * @return Number of elements.
 */
template<typename E>
constexpr uint8_t enum_size()
{
	return static_cast<uint8_t>(E::FIELDS_SIZE);
}

/**
 * @brief Fixed-size array indexed by enum class.
 *
 * Simplifies code by allowing strongly typed enum indexing.
 *
 * @tparam Enum Enum class type (must be contiguous, starting at 0).
 * @tparam T Stored type.
 * @tparam Size Size of the enum (should match number of fields).
 */

template<typename Enum, typename T, uint8_t Size>
class EnumArray {
public:
	static_assert(std::is_enum_v<Enum>, "EnumArray requires an enum type");

	/**
	 * @brief Access element by enum index.
	 */
	T& operator[](Enum index) { return m_data[static_cast<uint8_t>(index)]; }
	const T& operator[](Enum index) const { return m_data[static_cast<uint8_t>(index)]; }

	void insert(Enum index, const T& value)
	{
		uint8_t idx = static_cast<uint8_t>(index);
		if (idx != m_data.size()) {
			throw std::out_of_range("EnumArray: insertion index must be equal to current size");
		}
		m_data.push_back(value);
	}

	void insert(Enum index, T&& value)
	{
		uint8_t idx = static_cast<uint8_t>(index);
		if (idx != m_data.size()) {
			throw std::out_of_range("EnumArray: insertion index must be equal to current size");
		}
		m_data.push_back(std::move(value));
	}

	/**
	 * @brief Returns the number of elements in the array.
	 */
	std::size_t size() const noexcept { return m_data.size(); }

	/**
	 * @brief Returns iterator to the beginning.
	 */
	auto begin() noexcept { return m_data.begin(); }
	auto end() noexcept { return m_data.end(); }
	auto begin() const noexcept { return m_data.begin(); }
	auto end() const noexcept { return m_data.end(); }

private:
	boost::container::static_vector<T, Size> m_data;
};

/**
 * @brief Storage for field handlers indexed by enum.
 *
 * Designed to hold field accessors for a plugin schema.
 *
 * @tparam Enum Enum type used to represent individual fields.
 */

template<typename Enum>
using FieldHandlers = EnumArray<Enum, FieldHandler, enum_size<Enum>()>;

} // namespace ipxp