#pragma once

#include <cstdint>

namespace ipxp {

struct VariableLenghtInt {
	uint32_t value;
	uint8_t readBytes;
};

} // namespace ipxp