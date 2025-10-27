/**
 * @file
 * @brief Export data of bstats plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "burst.hpp"

#include <array>
#include <optional>
#include <span>

#include <boost/container/static_vector.hpp>
#include <timestamp.hpp>

namespace ipxp::process::burstStats {

/**
 * @class BurstStatsContext
 * @brief Class representing flow burst statistics.
 *
 * Contains packets, bytes and begin and end timestamps for each burst.
 */
class BurstStatsContext {
	static constexpr std::size_t MAX_BURST_COUNT = 15;

	DirectionalField<boost::container::static_vector<uint32_t, MAX_BURST_COUNT>> packets;
	DirectionalField<boost::container::static_vector<uint32_t, MAX_BURST_COUNT>> bytes;
	DirectionalField<boost::container::static_vector<amon::types::Timestamp, MAX_BURST_COUNT>>
		start;
	DirectionalField<boost::container::static_vector<amon::types::Timestamp, MAX_BURST_COUNT>> end;

public:
	/**
	 * @brief Returns a span over the packets for the given direction.
	 *
	 * @param direction The direction for which to retrieve the packet span.
	 * @return A span over the packets.
	 */
	std::span<const uint32_t> getPackets(const Direction direction) const noexcept
	{
		return {packets[direction].data(), static_cast<std::size_t>(packets[direction].size())};
	}

	/**
	 * @brief Returns a span over the bytes for the given direction.
	 *
	 * @param direction The direction for which to retrieve the byte span.
	 * @return A span over the bytes.
	 */
	std::span<const uint32_t> getBytes(const Direction direction) const noexcept
	{
		return std::span<const uint32_t>(
			bytes[direction].data(),
			static_cast<std::size_t>(bytes[direction].size()));
	}

	/**
	 * @brief Returns a span over the start timestamps for the given direction.
	 *
	 * @param direction The direction for which to retrieve the start timestamps span.
	 * @return A span over the start timestamps.
	 */
	std::span<const amon::types::Timestamp>
	getStartTimestamps(const Direction direction) const noexcept
	{
		return std::span<const amon::types::Timestamp>(
			start[direction].data(),
			static_cast<std::size_t>(start[direction].size()));
	}

	/**
	 * @brief Returns a span over the end timestamps for the given direction.
	 *
	 * @param direction The direction for which to retrieve the end timestamps span.
	 * @return A span over the end timestamps.
	 */
	std::span<const amon::types::Timestamp>
	getEndTimestamps(const Direction direction) const noexcept
	{
		return std::span<const amon::types::Timestamp>(
			end[direction].data(),
			static_cast<std::size_t>(end[direction].size()));
	}

	/**
	 * @brief Returns a view to the last observed burst.
	 *
	 * @param direction The direction for which to retrieve the last observed burst.
	 * @return A view to the last observed burst, or std::nullopt if no burst were added.
	 */
	inline std::optional<Burst> back(const Direction direction) noexcept
	{
		if (packets[direction].empty()) {
			return std::nullopt;
		}
		return std::make_optional<Burst>(
			{packets[direction].back(),
			 bytes[direction].back(),
			 start[direction].back(),
			 end[direction].back()});
	}

	/**
	 * @brief Adds new burst and returns it.
	 *
	 * @param direction The direction for which to add a burst.
	 * @return A view to the newly added burst, or std::nullopt if the storage is full.
	 */
	inline std::optional<Burst> push(const Direction direction) noexcept
	{
		if (packets[direction].size() == packets[direction].capacity()) {
			return std::nullopt;
		}

		packets[direction].push_back(0);
		bytes[direction].push_back(0);
		start[direction].push_back({});
		end[direction].push_back({});

		return back(direction);
	}
};

} // namespace ipxp::process::burstStats
