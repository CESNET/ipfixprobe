#pragma once

#include <array>

#include <directionalField.hpp>

namespace ipxp
{

struct PacketHistogramExport {
    constexpr static std::size_t HISTOGRAM_SIZE = 8;

	DirectionalField<std::array<uint32_t, HISTOGRAM_SIZE>> packetLengths;
	DirectionalField<std::array<uint32_t, HISTOGRAM_SIZE>> packetTimediffs;
};  

} // namespace ipxp

