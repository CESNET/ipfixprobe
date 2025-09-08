#pragma once

#include <vector>

#include <directionalField.hpp>
#include <tcpFlags.hpp>
#include <timestamp.hpp>

namespace ipxp
{

/**
 * @struct PacketStatsData
 * @brief Stores statistics and state information for a sequence of network packets.
 * 
 * This structure maintains vectors for packet lengths, TCP flags, timestamps, and packet directions. 
 * Also contains processing state that keeps info about each packet in both directions.
 * 
 */
struct PacketStatsData {
	/// Initial reserved size for the storage.
	constexpr static std::size_t INITIAL_SIZE = 5;
	/// Maximum storage size.
	constexpr static std::size_t MAX_SIZE = 30;

	/// Storage for lengths of the packets.
	std::vector<uint16_t> lengths;
	/// Storage for TCP flags of the packets.
	std::vector<TCPFlags> tcpFlags;
	/// Storage for timestamps of the packets.
	std::vector<Timestamp> timestamps;
	/// Storage for directions of the packets.
	std::vector<int8_t> directions;

	/**
	 * @brief Default constructor. Reserves initial storage space.
	 */
	PacketStatsData() noexcept
	{
		lengths.reserve(INITIAL_SIZE);
		tcpFlags.reserve(INITIAL_SIZE);
		timestamps.reserve(INITIAL_SIZE);
		directions.reserve(INITIAL_SIZE);
	}

	/**
	 * @brief Reserves maximum space for storage.
	 */
	void reserveMaxSize() noexcept
	{
		lengths.reserve(MAX_SIZE);
		tcpFlags.reserve(MAX_SIZE);
		timestamps.reserve(MAX_SIZE);
		directions.reserve(MAX_SIZE);
	}

	/**
	 * @brief Stores the last seen sequence, acknowledgment, length, and flags for each direction.
	 */
	struct {
		DirectionalField<uint32_t> lastSequence;
		DirectionalField<uint32_t> lastAcknowledgment;
		DirectionalField<std::size_t> lastLength;
		DirectionalField<TCPFlags> lastFlags;
	} processingState;
};

} // namespace ipxp

