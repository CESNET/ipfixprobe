/**
 * @file ipfixBasicList.hpp
 * @brief Class that implements a basic list for IPFIX elements.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "utils/byteUtils.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

#include <amon/types/Timestamp.hpp>
#include <boost/container/static_vector.hpp>
#include <fieldTypeConcepts.hpp>

namespace ipxp::output::ipfix {

/**
 * @class IPFIXBasicList
 * @brief Class representing a basic list for IPFIX elements.
 *
 * This class provides functionality to create and manage a basic list of IPFIX elements,
 * including calculating the size of the list and writing the list to a byte writer.
 *
 * @tparam ElementType The type of elements in the list. Must satisfy the FlowDataTypeVector
 * concept.
 */
template<process::FlowDataTypeVector ElementType = uint8_t>
class IPFIXBasicList {
	/// @brief Size of an empty list
	constexpr static inline std::size_t EMPTY_LIST_SIZE = 1UL;

	/// @brief Header length for list with more than 1 element
	constexpr static inline std::size_t LONG_HEADER_LENGTH = 3UL;

public:
	/**
	 * @brief Calculates the size of the IPFIX basic list.
	 * @return The size of the list in bytes.
	 */
	std::size_t getSize() const noexcept
	{
		if (m_elements.empty()) {
			return EMPTY_LIST_SIZE;
		}
		return LONG_HEADER_LENGTH + m_elements.size() * sizeof(ElementType);
	}

	/**
	 * @brief Constructs an IPFIXBasicList with the given elements.
	 * @param elements The elements to include in the list.
	 */
	IPFIXBasicList(std::span<const ElementType> elements) noexcept
		: m_elements(elements)
	{
	}

	/**
	 * @brief Writes the IPFIX basic list to the given byte writer.
	 * @param outputWriter The byte writer to write the list to.
	 */
	void writeTo(utils::ByteWriter& outputWriter) const noexcept
	{
		if (m_elements.empty()) {
			outputWriter.write(static_cast<uint8_t>(0));
			return;
		}

		appendLongHeader(outputWriter);
		for (const ElementType& element : m_elements) {
			if constexpr (std::is_same_v<ElementType, std::string>) {
				outputWriter.write(element);
			} else {
				outputWriter.write(utils::byteSwap(element));
			}
		}
	}

	/**
	 * @brief Default constructor for an empty IPFIX basic list.
	 */
	IPFIXBasicList() noexcept {};

private:
	constexpr static inline uint8_t LONG_HEADER_FLAG = 255;

	void appendLongHeader(utils::ByteWriter& outputWriter) const noexcept
	{
		outputWriter.write(LONG_HEADER_FLAG);
		outputWriter.write(static_cast<uint16_t>(0)); // Placeholder for length
	}

	const std::span<const ElementType> m_elements;
};

template<typename ElementType>
IPFIXBasicList(std::span<const ElementType>) -> IPFIXBasicList<const ElementType>;

} // namespace ipxp::output::ipfix