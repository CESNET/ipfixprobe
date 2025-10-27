/**
 * @file
 * @brief Provides QUIC version used to decrypt payload.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::quic {

/**
 * @enum QUICVersionId
 * @brief Enumerates QUIC version identifiers.
 */
enum class QUICVersionId : uint32_t {
	// Full versions
	facebook1 = 0xfaceb001,
	facebook2 = 0xfaceb002,
	facebook3 = 0xfaceb00d,
	facebook4 = 0xfaceb00f,
	facebook_experimental = 0xfaceb00e,
	facebook_experimental2 = 0xfaceb011,
	facebook_experimental3 = 0xfaceb013,
	facebook_mvfst_old = 0xfaceb000,
	facebook_mvfst_alias = 0xfaceb010,
	facebook_mvfst_alias2 = 0xfaceb012,
	facebook_v1_alias = 0xfaceb003,
	q_version2_draft00 = 0xff020000,
	q_version2_newest = 0x709a50c4,
	q_version2 = 0x6b3343cf,
	version_negotiation = 0x00000000,
	quic_newest = 0x00000001,
	picoquic1 = 0x50435130,
	picoquic2 = 0x50435131,
	// Patterns
	force_ver_neg_pattern = 0x0a0a0a0a,
	quant = 0x45474700,
	older_version = 0xff0000,
	quic_go = 0x51474f00,
	// unknown handshake salt TODO use version 1 as default?
	quicly = 0x91c17000,
	// https://github.com/microsoft/msquic/blob/d33bc56d5e11db52e2b34ae152ea598fd6e935c0/src/core/packet.c#L461
	// But version is different
	ms_quic = 0xabcd0000,

	ethz = 0xf0f0f0f0,
	telecom_italia = 0xf0f0f1f0,

	moz_quic = 0xf123f0c0,

	tencent_quic = 0x07007000,

	quinn_noise = 0xf0f0f2f0,

	quic_over_scion = 0x5c100000
};

/**
 * @enum QUICGeneration
 * @brief Enumerates QUIC generations.
 */
enum class QUICGeneration {
	V0, // IETF implementation
	V1,
	V2,
};

/**
 * @struct QUICVersion
 * @brief Calculates draft and generation based on QUIC version id.
 */
struct QUICVersion {
	uint8_t draft;
	QUICVersionId id;
	QUICGeneration generation;

	constexpr QUICVersion(const uint32_t id) noexcept
		: draft(static_cast<uint8_t>(id))
		, id(static_cast<QUICVersionId>(id))
		, generation()
	{
		// this is IETF implementation, older version used
		if (static_cast<QUICVersionId>(id >> 8) == QUICVersionId::older_version) {
			if (static_cast<uint8_t>(draft) >= 1 && static_cast<uint8_t>(draft) <= 34) {
				generation = QUICGeneration::V0;
				return;
			}
		}

		// This exists since version 29, but is still present in RFC9000.
		if (static_cast<QUICVersionId>(id & 0x0F0F0F0F) == QUICVersionId::force_ver_neg_pattern) {
			// Version 1
			draft = 35;
			generation = QUICGeneration::V1;
			return;
		}

		// Without further knowledge we assume QUIC version is 1.

		// Last nibble is zero
		switch (static_cast<QUICVersionId>(id & 0xfffffff0)) {
		case QUICVersionId::ms_quic:
			draft = 29;
			generation = QUICGeneration::V1;
			return;
		case QUICVersionId::ethz:
			[[fallthrough]];
		case QUICVersionId::telecom_italia:
			[[fallthrough]];
		case QUICVersionId::tencent_quic:
			[[fallthrough]];
		case QUICVersionId::quinn_noise:
			[[fallthrough]];
		case QUICVersionId::quic_over_scion:
			draft = 35;
			generation = QUICGeneration::V1;
			return;
		case QUICVersionId::moz_quic:
			draft = 14;
			generation = QUICGeneration::V1;
			return;
		default:
			break;
		}

		// Last Byte zero
		switch (static_cast<QUICVersionId>(id & 0xffffff00)) {
		case QUICVersionId::quant:
			generation = QUICGeneration::V0;
			return;
		case QUICVersionId::quic_go:
			[[fallthrough]];
		case QUICVersionId::quicly:
			draft = 35;
			generation = QUICGeneration::V1;
			return;
		default:
			break;
		}

		switch (static_cast<QUICVersionId>(id)) {
		case QUICVersionId::version_negotiation:
			// TODO verify: We return a value that has no salt assigned.
			draft = 1;
			generation = QUICGeneration::V1;
			return;
		// older mvfst version, but still used, based on draft 22, but salt 21 used
		case (QUICVersionId::facebook_mvfst_old):
			draft = 20;
			generation = QUICGeneration::V1;
			return;
		case (QUICVersionId::facebook1):
			draft = 22;
			generation = QUICGeneration::V1;
			return;
		// more used atm, salt 23 used
		case (QUICVersionId::facebook2):
		// 3 and 4 use default salt 23 according to mvfst:
		// https://github.com/facebook/mvfst/blob/e89b990eaec5787a7dca7750362ea530e7703bdf/quic/handshake/HandshakeLayer.cpp#L27
		case QUICVersionId::facebook3:
			[[fallthrough]];
		case QUICVersionId::facebook4:
			[[fallthrough]];
		case QUICVersionId::facebook_experimental:
			[[fallthrough]];
		case QUICVersionId::facebook_experimental2:
			[[fallthrough]];
		case QUICVersionId::facebook_experimental3:
			[[fallthrough]];
		case QUICVersionId::facebook_mvfst_alias:
			[[fallthrough]];
		case QUICVersionId::facebook_mvfst_alias2:
			draft = 27;
			generation = QUICGeneration::V1;
			return;
		// version 2 draft 00
		case QUICVersionId::quic_newest:
			draft = 35;
			generation = QUICGeneration::V1;
			return;
		case QUICVersionId::picoquic1:
		case QUICVersionId::picoquic2:
			draft = 36;
			generation = QUICGeneration::V1;
			return;
		case QUICVersionId::q_version2_draft00:
		// newest
		case QUICVersionId::q_version2_newest:
			draft = 100;
			generation = QUICGeneration::V2;
			return;
		case QUICVersionId::q_version2:
			draft = 101;
			generation = QUICGeneration::V2;
			return;
		case QUICVersionId::facebook_v1_alias:
			[[fallthrough]];
		default:
			draft = 255;
			generation = QUICGeneration::V1;
			return;
		}
	}
};

} // namespace ipxp::process::quic
