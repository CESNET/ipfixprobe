/**
 * @file
 * @brief Provides QUIC salt values for different QUIC versions.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "quicVersion.hpp"

#include <cstddef>
#include <optional>
#include <span>

#include <utils/spanUtils.hpp>

namespace ipxp::process::quic {

/**
 * @struct QUICSalt
 * @brief Creates salt used in QUIC payload decryption depending on the input QUIC version.
 */
struct QUICSalt {
	static std::optional<std::span<const std::byte>> createFor(const QUICVersion& version) noexcept
	{
		// version = quic_h1->version;
		// version = ntohl(version);
		//  this salt is used to draft 7-9
		static auto handshake_salt_draft_7
			= std::to_array<uint8_t>({0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e, 0xca, 0x1e, 0x9d,
									  0x36, 0xf3, 0x7f, 0xb2, 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39});
		// this salt is used to draft 10-16
		static auto handshake_salt_draft_10
			= std::to_array<uint8_t>({0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
									  0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38});
		// this salt is used to draft 17-20
		static auto handshake_salt_draft_17
			= std::to_array<uint8_t>({0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef,
									  0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0});
		// this salt is used to draft 21-22
		static auto handshake_salt_draft_21
			= std::to_array<uint8_t>({0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
									  0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a});
		// this salt is used to draft 23-28
		static auto handshake_salt_draft_23
			= std::to_array<uint8_t>({0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
									  0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02});
		// this salt is used to draft 29-32
		static auto handshake_salt_draft_29
			= std::to_array<uint8_t>({0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
									  0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99});
		// newest 33 -
		static auto handshake_salt_v1
			= std::to_array<uint8_t>({0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
									  0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a});
		static auto handshake_salt_v2_provisional
			= std::to_array<uint8_t>({0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18, 0x4a, 0x1d,
									  0x62, 0xca, 0x57, 0x04, 0x06, 0xea, 0x7a, 0xe3, 0xe5, 0xd3});
		static auto handshake_salt_v2
			= std::to_array<uint8_t>({0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
									  0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9});
		// picoquic
		static auto handshake_salt_picoquic_internal
			= std::to_array<uint8_t>({0x30, 0x67, 0x16, 0xd7, 0x63, 0x75, 0xd5, 0x55, 0x4b, 0x2f,
									  0x60, 0x5e, 0xef, 0x78, 0xd8, 0x33, 0x3d, 0xc1, 0xca, 0x36});

		if (version.id == QUICVersionId::version_negotiation) {
			// Error, version negotiation;
			return std::nullopt;
		}
		if (version.generation != QUICGeneration::V2 && version.id == QUICVersionId::quic_newest) {
			return toSpan<const std::byte>(handshake_salt_v1);
		}

		if (version.draft == 0) {
			return std::nullopt;
		}

		if (version.generation == QUICGeneration::V2 && version.draft <= 100) {
			return toSpan<const std::byte>(handshake_salt_v2_provisional);
		}
		if (version.generation == QUICGeneration::V2 && version.draft <= 101) {
			return toSpan<const std::byte>(handshake_salt_v2);
		}

		if (version.generation == QUICGeneration::V2) {
			return std::nullopt;
		}

		if (version.draft <= 9) {
			return toSpan<const std::byte>(handshake_salt_draft_7);
		}
		if (version.draft <= 16) {
			return toSpan<const std::byte>(handshake_salt_draft_10);
		}
		if (version.draft <= 20) {
			return toSpan<const std::byte>(handshake_salt_draft_17);
		}
		if (version.draft <= 22) {
			return toSpan<const std::byte>(handshake_salt_draft_21);
		}
		if (version.draft <= 28) {
			return toSpan<const std::byte>(handshake_salt_draft_23);
		}
		if (version.draft <= 32) {
			return toSpan<const std::byte>(handshake_salt_draft_29);
		}
		if (version.draft <= 35) {
			return toSpan<const std::byte>(handshake_salt_v1);
		}
		if (version.draft <= 36) {
			return toSpan<const std::byte>(handshake_salt_picoquic_internal);
		}

		return std::nullopt;
	}
};

} // namespace ipxp::process::quic
