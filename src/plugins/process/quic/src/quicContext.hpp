/**
 * @file
 * @brief Export data of QUIC plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "quicConnectionId.hpp"
#include "quicTemporalStorage.hpp"

#include <array>
#include <optional>
#include <span>
#include <vector>

#include <boost/container/static_vector.hpp>
#include <boost/static_string.hpp>

namespace ipxp::process::quic {

/**
 * @struct QUICContext
 * @brief Contains parsed QUIC values for export and processing state required to decrypt payloads.
 */
struct QUICContext {
	constexpr static std::size_t BUFFER_SIZE = 255;
	using ServerName = boost::static_string<BUFFER_SIZE>;
	ServerName serverName;

	using UserAgent = boost::static_string<BUFFER_SIZE>;
	UserAgent userAgent;

	constexpr static std::size_t MAX_PACKETS = 30;
	boost::container::static_vector<uint8_t, MAX_PACKETS> packetTypes;

	constexpr static std::size_t MAX_TLS_EXTENSIONS = 30;
	boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS> tlsExtensionTypes;
	boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS> tlsExtensionLengths;

	constexpr static std::size_t MAX_TLS_PAYLOAD_TO_SAVE = 1500;
	std::vector<std::byte> extensionsPayload;

	uint32_t quicVersion;
	uint32_t quicClientVersion;
	uint64_t quicTokenLength;
	uint8_t multiplexedCount;
	uint8_t quicZeroRTTCount;
	uint8_t clientHelloParsed;
	uint16_t serverPort;

	ConnectionId originalClientId;
	ConnectionId originalServerId;
	ConnectionId sourceId;
	ConnectionId retrySourceId;

	struct {
		QUICTemporalStorage temporalCIDStorage;
		std::size_t retryPacketCount = 0;
		std::optional<ConnectionId> initialConnectionId;
	} processingState;
};

} // namespace ipxp::process::quic
