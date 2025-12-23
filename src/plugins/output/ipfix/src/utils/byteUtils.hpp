/**
 * @file byteUtils.hpp
 * @brief Utility functions and classes for byte manipulation.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>
#include <functional>
#include <span>

#include <amon/types/IPAddress.hpp>
#include <fieldTypeConcepts.hpp>
#include <ipAddress.hpp>

namespace ipxp::output::ipfix::utils {

/**
 * @brief Appends the bytes of an integer or byte value to a destination container.
 * @tparam Integer The type of the value to append (integral or std::byte).
 * @param destination The container to which the bytes will be appended.
 * @param value The integer or byte value whose bytes will be appended.
 */
template<typename Integer>
	requires std::is_integral_v<Integer> || std::is_same_v<Integer, std::byte>
constexpr static void appendBytes(auto& destination, const Integer value)
{
	const auto bytes
		= std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), sizeof(Integer));
	destination.insert(destination.end(), bytes.begin(), bytes.end());
}

/**
 * @class ByteWriter
 * @brief An auxiliary class for writing bytes into a container. Hides underlying container.
 */
class ByteWriter {
public:
	using iterator_category = std::output_iterator_tag;
	using value_type = void;
	using difference_type = void;
	using pointer = void;
	using reference = void;

	/**
	 * @brief Creates a ByteWriter that appends bytes to the given container.
	 * @param container The container to which bytes will be appended.
	 * @return A ByteWriter instance.
	 */
	constexpr static ByteWriter makeByteWriter(auto& container) noexcept
	{
		return ByteWriter([&container](const std::span<const std::byte> data) {
			container.insert(container.end(), data.begin(), data.end());
		});
	}

	/**
	 * @brief Writes a value of type T to the underlying container.
	 * @tparam T The type of the value to write.
	 * @param value The value to write.
	 */
	template<typename T>
		requires process::FlowDataTypeScalar<T> || std::is_same_v<T, std::string>
		|| std::is_same_v<T, std::byte>
	void write(const T value)
	{
		if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>) {
			m_appendFunction(
				std::span<const std::byte>(
					reinterpret_cast<const std::byte*>(value.data()),
					value.size()));
		} else {
			m_appendFunction(
				std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), sizeof(T)));
		}
	}

private:
	explicit ByteWriter(std::function<void(const std::span<const std::byte>)> appendFunction)
		: m_appendFunction(std::move(appendFunction))
	{
	}

	std::function<void(const std::span<const std::byte>)> m_appendFunction;
};

/**
 * @brief Performs byte swap on integral and floating-point types.
 * @tparam T The type of the value to byte swap.
 * @param value The value to byte swap.
 * @return The byte-swapped value.
 */
template<typename T>
T byteSwap(const T value) noexcept
{
	if constexpr (std::is_integral_v<T>) {
		return std::byteswap(value);
	} else if constexpr (std::is_floating_point_v<T>) {
		using uint_t = std::conditional_t<sizeof(T) == sizeof(uint64_t), uint64_t, uint32_t>;
		return std::bit_cast<T>(std::byteswap(std::bit_cast<uint_t>(value)));
	} else if constexpr (
		std::is_same_v<T, amon::types::MACAddress> || std::is_same_v<T, amon::types::Timestamp>
		|| std::is_same_v<T, ipxp::IPAddressVariant> || std::is_same_v<T, bool>
		|| std::is_same_v<T, amon::types::IPv6> || std::is_same_v<T, amon::types::IPv4>
		|| std::is_same_v<T, std::byte> || std::is_same_v<T, std::string_view>
		|| std::is_same_v<T, std::string> || std::is_same_v<T, std::byte>) {
		return value;
	} else {
		static_assert(sizeof(T) == 0, "byteSwap not implemented for this type");
		return {};
	}
}

} // namespace ipxp::output::ipfix::utils