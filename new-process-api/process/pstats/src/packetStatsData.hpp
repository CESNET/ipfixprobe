#pragma once

#include <vector>

#include <directionalField.hpp>
#include <tcpFlags.hpp>

namespace ipxp
{

struct PacketStatsData {
	constexpr static std::size_t MAX_SIZE = 30;

	std::vector<uint16_t> lengths;
	std::vector<TcpFlags> tcpFlags;
	std::vector<uint64_t> timestamps;
	std::vector<int8_t> directions;

	struct {
		DirectionalField<uint32_t> lastSequence;
		DirectionalField<uint32_t> lastAcknowledgment;
		DirectionalField<std::size_t> lastLength;
		DirectionalField<TcpFlags> lastFlags;
	} processingState;
};  

} // namespace ipxp

