#pragma once

#include <array>

#include <directionalField.hpp>

namespace ipxp
{

struct PacketHistogramData {
    constexpr static std::size_t HISTOGRAM_SIZE = 8;
	DirectionalField<std::array<uint32_t, HISTOGRAM_SIZE>> packetLengths;
	DirectionalField<std::array<uint32_t, HISTOGRAM_SIZE>> packetTimediffs;

	struct {
		DirectionalField<std::optional<uint64_t>> m_lastTimestamps;
		bool m_countEmptyPackets{false};
	} processingState;

};  

} // namespace ipxp

