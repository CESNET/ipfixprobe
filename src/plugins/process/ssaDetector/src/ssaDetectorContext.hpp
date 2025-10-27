/**
 * @file ssaDetectorContext.hpp
 * @brief Definition of SSADetectorContext struct for SSA Detector plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "packetStorage.hpp"

#include <cstdint>

#include <boost/container/static_vector.hpp>

namespace ipxp::process::ssaDetector {

/**
 * @struct SSADetectorContext
 * @brief Stores parsed SSA Detector data that will be exported.
 */
struct SSADetectorContext {
	constexpr static std::size_t MAX_SUSPECT_LENGTHS = 100;

	uint8_t confidence;

	struct {
		PacketStorage synPackets;
		PacketStorage synAckPackets;
		std::size_t suspects {0};

		boost::container::static_vector<std::size_t, MAX_SUSPECT_LENGTHS> suspectLengths;
	} processingState;
};

} // namespace ipxp::process::ssaDetector
