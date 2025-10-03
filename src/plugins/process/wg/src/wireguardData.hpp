#pragma once

#include <cstdint>

#include <directionalField.hpp>

namespace ipxp {

struct WireguardData {
	uint8_t confidence;
	DirectionalField<std::optional<uint32_t>> peer;
};

} // namespace ipxp
