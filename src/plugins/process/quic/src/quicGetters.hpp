/**
 * @file quicGetters.hpp
 * @brief Getters for QUIC plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "quicContext.hpp"

#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::quic {

inline constexpr const QUICContext& asQUICContext(const void* context) noexcept
{
	return *static_cast<const QUICContext*>(context);
}

// QUICField::QUIC_SNI
inline constexpr auto getQUICSNIField
	= [](const void* context) { return toStringView(asQUICContext(context).serverName); };

// QUICField::QUIC_USER_AGENT
inline constexpr auto getQUICUserAgentField
	= [](const void* context) { return toStringView(asQUICContext(context).userAgent); };

// QUICField::QUIC_VERSION
inline constexpr auto getQUICVersionField
	= [](const void* context) { return asQUICContext(context).quicVersion; };

// QUICField::QUIC_CLIENT_VERSION
inline constexpr auto getQUICClientVersionField
	= [](const void* context) { return asQUICContext(context).quicClientVersion; };

// QUICField::QUIC_TOKEN_LENGTH
inline constexpr auto getQUICTokenLengthField
	= [](const void* context) { return asQUICContext(context).quicTokenLength; };

// QUICField::QUIC_OCCID
inline constexpr auto getQUICOCCIDField
	= [](const void* context) { return toStringView(asQUICContext(context).originalClientId); };

// QUICField::QUIC_OSCID
inline constexpr auto getQUICOSCCIDField
	= [](const void* context) { return toStringView(asQUICContext(context).originalServerId); };

// QUICField::QUIC_SCID
inline constexpr auto getQUICSCIDField
	= [](const void* context) { return toStringView(asQUICContext(context).sourceId); };

// QUICField::QUIC_RETRY_SCID
inline constexpr auto getQUICRetrySCIDField
	= [](const void* context) { return toStringView(asQUICContext(context).retrySourceId); };

// QUICField::QUIC_MULTIPLEXED
inline constexpr auto getQUICMultiplexedField
	= [](const void* context) { return asQUICContext(context).multiplexedCount; };

// QUICField::QUIC_ZERO_RTT
inline constexpr auto getQUICZeroRTTField
	= [](const void* context) { return asQUICContext(context).quicZeroRTTCount; };

// QUICField::QUIC_SERVER_PORT
inline constexpr auto getQUICServerPortField
	= [](const void* context) { return asQUICContext(context).serverPort; };

// QUICField::QUIC_PACKETS
inline constexpr auto getQUICPacketsField
	= [](const void* context) { return toSpan<const uint8_t>(asQUICContext(context).packetTypes); };

// QUICField::QUIC_CH_PARSED
inline constexpr auto getQUICCHParsedField
	= [](const void* context) { return asQUICContext(context).clientHelloParsed; };

// QUICField::QUIC_TLS_EXT_TYPE
inline constexpr auto getQUICTLSExtTypeField = [](const void* context) {
	return toSpan<const uint16_t>(asQUICContext(context).tlsExtensionTypes);
};

// QUICField::QUIC_TLS_EXT_LEN
inline constexpr auto getQUICTLSExtLenField = [](const void* context) {
	return toSpan<const uint16_t>(asQUICContext(context).tlsExtensionLengths);
};

// QUICField::QUIC_TLS_EXT
inline constexpr auto getQUICTLSExtField
	= [](const void* context) { return toStringView(asQUICContext(context).extensionsPayload); };

} // namespace ipxp::process::quic