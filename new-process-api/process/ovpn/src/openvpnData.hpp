#pragma once

#include <array>
#include <boost/container/static_vector.hpp>
#include <optional>
#include <span>

#include <ipAddress.hpp>

namespace ipxp
{

struct OpenVPNData {
	uint8_t vpnConfidence;

	OpenVPNProcessingState processingState;
};  

} // namespace ipxp

