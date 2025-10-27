/**
 * @file
 * @brief Export data of packet stats plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "packetStatsStorage.hpp"

#include <variant>
#include <vector>

#include <directionalField.hpp>
#include <tcpFlags.hpp>
#include <timestamp.hpp>

namespace ipxp::process::packet_stats {

/**
 * @struct PacketStatsContext
 * @brief Stores statistics and state information for a sequence of network packets.
 *
 * This structure maintains vectors for packet lengths, TCP flags, timestamps, and packet
 * directions. Also contains processing state that keeps info about each packet in both directions.
 *
 */
struct PacketStatsContext {
	/// Initial reserved size for the storage.
	constexpr static std::size_t INITIAL_SIZE = 5;
	/// Maximum storage size.
	constexpr static std::size_t MAX_SIZE = 30;

	std::variant<
		std::unique_ptr<PacketStatsStorage<INITIAL_SIZE>>,
		std::unique_ptr<PacketStatsStorage<MAX_SIZE>>>
		storage = std::make_unique<PacketStatsStorage<INITIAL_SIZE>>();

	/**
	 * @brief Default constructor. Reserves initial storage space.
	 */
	/*PacketStatsData() noexcept
	{
		lengths.reserve(INITIAL_SIZE);
		tcpFlags.reserve(INITIAL_SIZE);
		timestamps.reserve(INITIAL_SIZE);
		directions.reserve(INITIAL_SIZE);
	}*/

	/**
	 * @brief Reserves maximum space for storage.
	 */
	void reserveMaxSize() noexcept
	{
		auto newStorage = std::make_unique<PacketStatsStorage<MAX_SIZE>>(
			*std::get<std::unique_ptr<PacketStatsStorage<INITIAL_SIZE>>>(storage));
		storage = std::move(newStorage);
		/*lengths.reserve(MAX_SIZE);
		tcpFlags.reserve(MAX_SIZE);
		timestamps.reserve(MAX_SIZE);
		directions.reserve(MAX_SIZE);*/
	}

	/**
	 * @brief Stores the last seen sequence, acknowledgment, length, and flags for each direction.
	 */
	struct {
		DirectionalField<uint32_t> lastSequence;
		DirectionalField<uint32_t> lastAcknowledgment;
		DirectionalField<std::size_t> lastLength;
		DirectionalField<TCPFlags> lastFlags;
		uint8_t currentStorageSize {0};
	} processingState;
};

} // namespace ipxp::process::packet_stats
