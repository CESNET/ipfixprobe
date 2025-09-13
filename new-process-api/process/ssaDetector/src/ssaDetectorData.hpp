#pragma once

#include <cstdint>

#include "packetStorage.hpp"

namespace ipxp
{

struct SSADetectorData {
	constexpr static std::size_t MAX_SUSPECT_LENGTHS = 100;
	
	uint8_t confidence;

	struct {
		PacketStorage synPackets;
		PacketStorage synAckPackets;
		std::size_t suspects{0};

		boost::container::static_vector<std::size_t, MAX_SUSPECT_LENGTHS> suspectLengths;
	} processingState;
};  

} // namespace ipxp

