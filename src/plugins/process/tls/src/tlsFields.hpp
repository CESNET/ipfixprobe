/**
 * @file
 * @brief Definition of TLS fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::tls {

/**
 * @enum TLSFields
 * @brief Enumerates the fields exported by the TLS plugin.
 * These enum values are used to index field handlers for this plugin.
 */
enum class TLSFields : std::size_t {
	TLS_SNI = 0,
	TLS_JA3,
	TLS_JA4,
	TLS_ALPN,
	TLS_VERSION,
	TLS_EXT_TYPE,
	TLS_EXT_LEN,
	FIELDS_SIZE,
};

} // namespace ipxp::process::tls
