/**
 * @file
 * @brief Export fields of QUIC plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::quic {

/**
 * @enum QUICFields
 * @brief Enumerates the fields exported by the QUIC plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class QUICFields : std::size_t {
	QUIC_SNI = 0,
	QUIC_USER_AGENT,
	QUIC_VERSION,
	QUIC_CLIENT_VERSION,
	QUIC_TOKEN_LENGTH,
	QUIC_OCCID,
	QUIC_OSCID,
	QUIC_SCID,
	QUIC_RETRY_SCID,
	QUIC_MULTIPLEXED,
	QUIC_ZERO_RTT,
	QUIC_SERVER_PORT,
	QUIC_PACKETS,
	QUIC_CH_PARSED,
	QUIC_TLS_EXT_TYPE,
	QUIC_TLS_EXT_LEN,
	QUIC_TLS_EXT,
	FIELDS_SIZE,
};

} // namespace ipxp::process::quic
