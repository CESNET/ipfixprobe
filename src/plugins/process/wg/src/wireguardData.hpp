/**
 * @file
 * @brief Definition of Wireguard data structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>
#include <optional>

#include <directionalField.hpp>

namespace ipxp {

/**
 * @struct WireguardData
 * @brief Struct representing Wireguard export data.
 */
struct WireguardData {
	uint8_t confidence;
	DirectionalField<std::optional<uint32_t>> peer;
};

} // namespace ipxp
