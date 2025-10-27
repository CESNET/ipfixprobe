/**
 * @file
 * @brief Defines the TLSExtension struct for representing TLS extensions.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "tlsExtensionType.hpp"

#include <cstdint>
#include <span>

namespace ipxp::process {

/**
 * @struct TLSExtension
 * @brief Represents a TLS extension with its type and payload.
 */
struct TLSExtension {
	TLSExtensionType type;
	std::span<const std::byte> payload;
};

} // namespace ipxp::process
