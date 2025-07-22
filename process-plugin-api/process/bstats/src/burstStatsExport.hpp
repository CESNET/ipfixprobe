#pragma once

#include <array>
#include <boost/container/static_vector.hpp>
#include <optional>
#include <span>

#include "burst.hpp"

namespace ipxp
{

struct BurstStatsExport {
private:
	static constexpr std::size_t MAX_BURST_COUNT = 15;
	/*typedef enum eHdrFieldID {
		SPkts = 1050,
		SBytes = 1051,
		SStart = 1052,
		SStop = 1053,
		DPkts = 1054,
		DBytes = 1055,
		DStart = 1056,
		DStop = 1057
	} eHdrFieldID;*/

	DirectionalField<uint16_t> burst_count;
	DirectionalField<uint8_t> burst_empty;

	DirectionalField<boost::container::static_vector<uint32_t, MAX_BURST_COUNT>> packets;
	DirectionalField<boost::container::static_vector<uint32_t, MAX_BURST_COUNT>> bytes;
	DirectionalField<boost::container::static_vector<timeval, MAX_BURST_COUNT>> start;
	DirectionalField<boost::container::static_vector<timeval, MAX_BURST_COUNT>> end;

public:

	std::span<const uint32_t> getPackets(const Direction direction) const noexcept
	{
		return {packets[direction].data(), static_cast<std::size_t>(packets[direction].size())};
	}
	
	std::span<const uint32_t> getBytes(const Direction direction) const noexcept
	{
		return std::span<uint32_t>(packets[direction].data(), packets[direction].size());
	}

	std::span<const uint32_t> getStartTimestamps(const Direction direction) const noexcept
	{
		return std::span<uint32_t>(packets[direction].data(), packets[direction].size());
	}

	std::span<const uint32_t> getEndTimestamps(const Direction direction) const noexcept
	{
		return std::span<const uint32_t>(packets[direction].begin(), packets[direction].end());
	}

	inline
	std::optional<Burst> back(const Direction direction) noexcept
	{
		if (packets[direction].empty()) {
			return std::nullopt;
		}
		return std::make_optional<Burst>({
			packets[direction].back(),
			bytes[direction].back(),
			start[direction].back(),
			end[direction].back()
		});
	}

	inline
	std::optional<Burst> push(const Direction direction) noexcept
	{
		if (packets[direction].size() == packets[direction].max_size()) {
			return std::nullopt;
		}

		packets[direction].push_back(0);
		bytes[direction].push_back(0);
		start[direction].push_back({});
		end[direction].push_back({});

		return back(direction);
	}


};  

} // namespace ipxp

