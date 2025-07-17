#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <variant>

namespace ipxp {

/**
 * @brief Accessor for reading a scalar field of type T from a binary structure using offset.
 *
 * Typically used when the field is stored at a known offset in a flat structure.
 *
 * @tparam T Type of the field (e.g. uint32_t, float, etc.).
 */
template<typename T>
struct ScalarAccessor {
	/// Construct accessor using byte offset from the base pointer.
	explicit constexpr ScalarAccessor(std::size_t offset) noexcept
		: offset(offset)
	{
	}

	/// Read the scalar value from the provided memory.
	T operator()(const void* data) const
	{
		return *reinterpret_cast<const T*>(static_cast<const char*>(data) + offset);
	}

	/// Byte offset of the field in the source structure.
	std::size_t offset;
};

/**
 * @brief Accessor for reading a read-only vector-like field using a lambda function.
 *
 * This accessor supports any container that can be viewed as `std::span<const T>`,
 * such as:
 *  - `std::vector<T>`
 *  - `std::array<T, N>`
 *  - C-style arrays `T[N]` (when the size is known)
 *  - any custom container or accessor function returning `std::span<const T>`
 *
 *
 * @tparam T Element type of the vector (e.g. `uint64_t`)
 */
template<typename T>
struct VectorAccessor {
	/// Type of the getter function that extracts a span from the given structure pointer.
	using GetterFunc = std::function<std::span<const T>(const void*)>;

	/// Construct the accessor with a user-supplied lambda or function.
	explicit VectorAccessor(GetterFunc func)
		: func(std::move(func))
	{
	}

	/// Call the accessor to get a span of values from the provided structure pointer.
	std::span<const T> operator()(const void* data) const { return func(data); }

private:
	GetterFunc func;
};

// Type-erased scalar getter for supported field types
using ScalarValueGetter = std::variant<
	ScalarAccessor<uint8_t>,
	ScalarAccessor<uint16_t>,
	ScalarAccessor<uint32_t>,
	ScalarAccessor<uint64_t>,
	ScalarAccessor<int8_t>,
	ScalarAccessor<int16_t>,
	ScalarAccessor<int32_t>,
	ScalarAccessor<int64_t>,
	ScalarAccessor<float>,
	ScalarAccessor<double>>;

// Type-erased vector getter for supported field types
using VectorValueGetter = std::variant<
	VectorAccessor<uint8_t>,
	VectorAccessor<uint16_t>,
	VectorAccessor<uint32_t>,
	VectorAccessor<uint64_t>,
	VectorAccessor<int8_t>,
	VectorAccessor<int16_t>,
	VectorAccessor<int32_t>,
	VectorAccessor<int64_t>,
	VectorAccessor<float>,
	VectorAccessor<double>,
	VectorAccessor<std::string>>;

/**
 * @brief Generic (type-erased) value getter that supports both scalar and vector types.
 *
 * Used in output fields to provide unified access to underlying data.
 */
using GenericValueGetter = std::variant<ScalarValueGetter, VectorValueGetter>;

} // namespace ipxp