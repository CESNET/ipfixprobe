/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file quic_parser.cpp
 * \brief Class for parsing quic traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * \date 2023
 */

#include "quicParser.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <arpa/inet.h> 
#include <array>
#include <limits>

#include "quicVersion.hpp"
#include "quicPacketType.hpp"
#include "quicHeaderView.hpp"

#ifdef DEBUG_QUIC
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_QUIC
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

namespace ipxp {
QUICParser::QUICParser()
{
	quic_h1 = nullptr;
	quic_h2 = nullptr;
	payload = nullptr;

	header_len = 0;
	payload_len = 0;
	payload_len_offset = 0;

	dcid = nullptr;
	dcid_len = 0;
	initial_dcid = nullptr;
	initial_dcid_len = 0;
	scid = nullptr;
	scid_len = 0;
	pkn = nullptr;
	sample = nullptr;
	salt = nullptr;
	final_payload = nullptr;
	parsed_initial = 0;
	is_version2 = false;
	packet_type = UNKNOWN;
	packets = 0;
	token_length = QUIC_UNUSED_VARIABLE_LENGTH_INT;
	zero_rtt = 0;
	server_port = 0;
	pkn_len = 0;
	tls_hs_type = 0;
	parsed_client_hello = false;

	memset(quic_tls_ext_type, 0, sizeof(quic_tls_ext_type));
	quic_tls_ext_type_pos = 0;

	memset(quic_tls_extension_lengths, 0, sizeof(quic_tls_extension_lengths));
	quic_tls_extension_lengths_pos = 0;

	memset(quic_tls_ext, 0, sizeof(quic_tls_ext));
	quic_tls_ext_pos = 0;
}
void QUICParser::quic_get_tls_ext_type(uint16_t* tls_ext_type_toset)
{
	// *2 since 16 bit instead of 8
	memcpy(tls_ext_type_toset, quic_tls_ext_type, quic_tls_ext_type_pos * 2);
}

void QUICParser::quic_get_tls_ext_type_len(uint16_t& tls_ext_type_len_toset)
{
	tls_ext_type_len_toset = quic_tls_ext_type_pos;
}

void QUICParser::quic_get_tls_ext(char* in)
{
	memcpy(in, quic_tls_ext, quic_tls_ext_pos);
	return;
}

void QUICParser::quic_get_tls_ext_len(uint16_t& tls_ext_len_toset)
{
	tls_ext_len_toset = quic_tls_ext_pos;
}

void QUICParser::quic_get_tls_extension_lengths(uint16_t* tls_extensions_len)
{
	memcpy(tls_extensions_len, quic_tls_extension_lengths, quic_tls_extension_lengths_pos * 2);
}

void QUICParser::quic_get_tls_extension_lengths_len(uint8_t& tls_extensions_length_len_toset)
{
	tls_extensions_length_len_toset = quic_tls_extension_lengths_pos;
}

uint8_t QUICParser::quic_get_packet_type()
{
	return packet_type;
}

uint8_t QUICParser::quic_get_parsed_ch()
{
	if (parsed_client_hello) {
		return 1;
	}
	return 0;
}

uint8_t QUICParser::quic_get_tls_hs_type()
{
	return tls_hs_type;
}

void QUICParser::quic_get_zero_rtt(uint8_t& zero_rtt_toset)
{
	zero_rtt_toset = zero_rtt;
}

void QUICParser::quic_get_version(uint32_t& version_toset)
{
	version_toset = version;
	return;
}

void QUICParser::quic_get_packets(uint8_t& packets_toset)
{
	packets_toset = packets;
	return;
}

void QUICParser::quic_get_token_length(uint64_t& token_len_toset)
{
	token_len_toset = token_length;
	return;
}

uint16_t QUICParser::quic_get_server_port()
{
	return server_port;
}

void QUICParser::quic_get_parsed_initial(uint8_t& to_set)
{
	to_set = parsed_initial;
	return;
}

void QUICParser::quic_get_dcid_len(uint8_t& scid_length_toset)
{
	scid_length_toset = dcid_len;
	return;
}

void QUICParser::quic_get_scid_len(uint8_t& scid_length_toset)
{
	scid_length_toset = scid_len;
	return;
}

void QUICParser::quic_get_tls_extensions(char* in)
{
	memcpy(in, quic_tls_ext, quic_tls_ext_pos);
	return;
}

void QUICParser::quic_get_dcid(char* in)
{
	memcpy(in, dcid, dcid_len);
	return;
}

void QUICParser::quic_get_scid(char* in)
{
	memcpy(in, scid, scid_len);
	return;
}

void QUICParser::quic_get_sni(char* in)
{
	memcpy(in, sni, BUFF_SIZE);
	return;
}

void QUICParser::quic_get_user_agent(char* in)
{
	memcpy(in, user_agent, BUFF_SIZE);
	return;
}








 // QUICPlugin::quic_derive_n_set

 // QUICPlugin::quic_derive_secrets




 // QUICPlugin::quic_decrypt_initial_header

 // QUICPlugin::quic_decrypt_payload

bool QUICParser::quic_check_frame_type(uint8_t* where, FRAME_TYPE frame_type)
{
	return (*where) == frame_type;
}





 // QUICParser::quic_reassemble_frames

void QUICParser::quic_initialze_arrays()
{
	// buffer for decrypted payload
	memset(decrypted_payload, 0, CURRENT_BUFFER_SIZE);
	// buffer for reassembled payload
	memset(assembled_payload, 0, CURRENT_BUFFER_SIZE);
	// buffer for quic header
	memset(tmp_header_mem, 0, MAX_HEADER_LEN);
}



bool QUICParser::quic_check_initial(uint8_t packet0)
{
	// The fixed bit, might be greased. We assume greasing for all packets
	// RFC 9287
	// version 1 (header form:long header(1) | fixed bit:fixed(1/0) | long packet type:initial(00)
	// --> 1000 --> 8)
	if ((packet0 & 0xB0) == 0x80) {
		return true;
	}
	// version 2 (header form:long header(1) | fixed bit:fixed(1)/0 | long packet type:initial(01)
	// --> 1001 --> 9)
	else if (is_version2 && ((packet0 & 0xB0) == 0x90)) {
		return true;
	} else {
		return false;
	}
}

bool QUICParser::quic_check_min_initial_size(const Packet& pkt)
{
	if (pkt.payload_len < QUIC_MIN_PACKET_LENGTH) {
		return false;
	}
	return true;
}

uint32_t read_uint32_t(const uint8_t* ptr, uint8_t offset)
{
	uint32_t val;
	memcpy(&val, ptr + offset, sizeof(uint32_t));
	return val;
}

constexpr 
bool QUICParser::parseInitialHeader(std::span<const std::byte> payload, 
	const PacketType packetType) noexcept
{
	const std::optional<QUICInitialHeaderView> initialHeaderView
		= QUICInitialHeaderView::createFromPayload(payload, packetType);
	if (!initialHeaderView.has_value()) {
		return false;
	}

	return true;
}

constexpr static
std::optional<std::span<const std::byte, 16>>
parseRetryPacket(std::span<const std::byte> payload) noexcept
{
	const std::optional<VariableLengthInt> token
		= readQUICVariableLengthInt(payload);
	if (!token.has_value()) {
		return std::nullopt;
	}

	return std::span<const std::byte, 16>(&payload[token->length()], 16);
}

bool QUICParser::quic_parse_headers(std::span<const std::byte> payload) noexcept
{
	// Handle coalesced packets
	// 7 because (1B QUIC LH, 4B Version, 1 B SCID LEN, 1B DCID LEN)
	uint64_t stored_payload_len;
	while (payload.size() >= QUIC_MIN_PACKET_LENGTH) {

		// TODO CHECK IF SUBSPAN NOT STARTS AFTER SPAN END
		const std::optional<QUICHeaderView> headerView
			= QUICHeaderView::createFrom(payload.subspan(offset));
		if (!headerView.has_value()) {
			break;
		}

		const QUICHeaderView::PacketType packetType = headerView->getPacketType();
		switch (packetType) {
		case QUICHeaderView::PacketType::ZERO_RTT:{

			const std::optional<VariableLengthInt> restPayloadLength
			 	= readQUICVariableLengthInt(data.subspan(headerView->getLength()));
			if (!restPayloadLength.has_value()) {
				return false;
			}

			if (m_zeroRTTPackets != std::numeric_limits<uint8_t>::max()) {
				m_zeroRTTPackets++;
			}

			data = data.subspan(headerView->getLength() 
				+ restPayloadLength->value + restPayloadLength->length);
			break;
		}
		case QUICHeaderView::PacketType::HANDSHAKE:{

			const std::optional<VariableLengthInt> restPayloadLength
			 	= readQUICVariableLengthInt(data.subspan(headerView->getLength()));
			if (!restPayloadLength.has_value()) {
				return false;
			}

			if (restPayloadLength->value > MAX_PAYLOAD_BUFFER_SIZE) {
				return false;
			}

			data = data.subspan(headerView->getLength() 
				+ restPayloadLength->value + restPayloadLength->length);
			break;
		}
		case QUICHeaderView::PacketType::INITIAL:
			// TODO USE FEW DCIDS
			if (!parseInitialHeader(data, packetType)) {
				return false;
			}

			stored_payload_len = payload_len;
			if (!parsed_initial) {
				// Not yet parsed a CH, try to parse as CH with inherited DCID
				quic_parse_initial(pkt, pkt_payload_pointer, offset);
				// If still not parsed, try with DCID from current packet.
				// Session resumption is such a case.
				if (!parsed_initial) {
					quic_tls_extension_lengths_pos = 0;
					// len = 0 forces reading DCID from current packet
					initial_dcid_len = 0;
					// Increment by tag_len, since subsequent function is not stateless.
					payload_len += payload_len_offset;
					// Undo side effect from QUICParser::quic_decrypt_initial_header
					payload = payload - pkn_len;
					payload_len += pkn_len;
					quic_parse_initial(pkt, pkt_payload_pointer, offset);
				}
			}
			offset += stored_payload_len;
			break;
		case QUICPacket::Type::RETRY:
			const std::optional<std::span<const std::byte, 16>> integrityTag 
				= parseRetryPacket(payload);
			// 16 - Integrity tag
			token_length = pkt_payload_end - payload_pointer - offset - 16;
			if (!quic_check_pointer_pos((pkt_payload_pointer + offset), pkt_payload_end)) {
				return false;
			}
			offset += token_length;
			if (!quic_check_pointer_pos((pkt_payload_pointer + offset), pkt_payload_end)) {
				return false;
			}
			break;
		}

		if (!quic_set_server_port(pkt)) {
			DEBUG_MSG("Error, extracting server port");
			return false;
		}

		if (packet_type == RETRY) {
			break;
		}
	}

	// Update packet type to most specific, i.e., Initial
	if (packets & F_INITIAL) {
		packet_type = INITIAL;
	}

	return packets;
} // QUICPlugin::quic_parse_data








bool QUICParser::quic_check_quic_long_header_packet(
	const uint8_t l4Protocol, std::span<const std::byte> payload,
	char* initial_packet_dcid,
	uint8_t& initial_packet_dcid_length)
{
	initial_dcid_len = initial_packet_dcid_length;
	initial_dcid = (uint8_t*) initial_packet_dcid;

	if (!hasQUICBitSet(packet.payload[0])) {
		return false;
	}

	if (!hasLongHeader(l4Protocol, payload[0])) {
		return false;
	}

	quic_initialze_arrays();
	if (!quic_parse_headers(pkt, false)) {
		return false;
	}
	return true;
}

constexpr static
std::optional<std::span<const uint8_t, 20>> 
getSalt(const QUICVersion& version) noexcept
{
	//version = quic_h1->version;
	//version = ntohl(version);
	// this salt is used to draft 7-9
	static auto handshake_salt_draft_7 = std::to_array<uint8_t>(
		{0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e, 0xca, 0x1e, 0x9d,
		   0x36, 0xf3, 0x7f, 0xb2, 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39});
	// this salt is used to draft 10-16
	static auto handshake_salt_draft_10 = std::to_array<uint8_t>(
		{0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
		   0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38});
	// this salt is used to draft 17-20
	static auto handshake_salt_draft_17 = std::to_array<uint8_t>(
		{0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef,
		   0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0});
	// this salt is used to draft 21-22
	static auto handshake_salt_draft_21 = std::to_array<uint8_t>(
		{0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
		   0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a});
	// this salt is used to draft 23-28
	static auto handshake_salt_draft_23 = std::to_array<uint8_t>(
		{0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
		   0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02});
	// this salt is used to draft 29-32
	static auto handshake_salt_draft_29 = std::to_array<uint8_t>(
		{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		   0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99});
	// newest 33 -
	static auto handshake_salt_v1 = std::to_array<uint8_t>(
		{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		   0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a});
	static auto handshake_salt_v2_provisional = std::to_array<uint8_t>(
		{0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18, 0x4a, 0x1d,
		   0x62, 0xca, 0x57, 0x04, 0x06, 0xea, 0x7a, 0xe3, 0xe5, 0xd3});
	static auto handshake_salt_v2 = std::to_array<uint8_t>(
		{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		   0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9});
	// picoquic
	static auto handshake_salt_picoquic_internal = std::to_array<uint8_t>(
		{0x30, 0x67, 0x16, 0xd7, 0x63, 0x75, 0xd5, 0x55, 0x4b, 0x2f,
		   0x60, 0x5e, 0xef, 0x78, 0xd8, 0x33, 0x3d, 0xc1, 0xca, 0x36});

	if (version.id == QUICVersionId::version_negotiation) {
		//Error, version negotiation;
		return std::nullopt;
	}
	if (version.generation != QUICGeneration::V2 
		&& version.id == QUICVersionId::quic_newest) {
		return toSpan(handshake_salt_v1);
	}

	if (version.draft == 0 ) {
		return std::nullopt;
	}

	if (version.generation == QUICGeneration::V2 
		&& version.draft <= 100) {
		return toSpan(handshake_salt_v2_provisional);
	}
	if (version.generation == QUICGeneration::V2 
		&& version.draft <= 101) {
		return toSpan(handshake_salt_v2);
	}

	if (version.generation == QUICGeneration::V2) {
		return std::nullopt;
	}

	if (version.draft <= 9) {
		return toSpan(handshake_salt_draft_7);
	}
	if (version.draft <= 16) {
		return toSpan(handshake_salt_draft_10);
	}
	if (version.draft <= 20) {
		return toSpan(handshake_salt_draft_17);
	}
	if (version.draft <= 22) {
		return toSpan(handshake_salt_draft_21);
	}
	if (version.draft <= 28) {
		return toSpan(handshake_salt_draft_23);
	} 
	if (version.draft <= 32) {
		return toSpan(handshake_salt_draft_29);
	}
	if (version.draft <= 35) {
		return toSpan(handshake_salt_v1);
	} 
	if (version.draft <= 36) {
		return toSpan(handshake_salt_picoquic_internal);
	}
	
	return std::nullopt;
} // QUICParser::quic_obtain_version

constexpr static
std::optional<QUICHeaderData> parseHeader(std::span<const std::byte> header) noexcept
{
	QUICHeaderData headerData;

	const std::optional<FirstQUICHeader> firstHeader 
		= FirstQUICHeader::createFromPayload(payload);
	if (!firstHeader.has_value()) {
		return std::nullopt;
	}

	const std::optional<std::span<const std::uint8_t, 20>> salt 
		= getSalt(firstHeader->getVersion());
	if (!salt.has_value()) {
		// Error, version not supported;
		return std::nullopt;
	}

	headerData.packetType = QUICPacket::getType(version, firstHeader->headerForm);

	const std::optional<QUICInitialHeaderView> initialHeaderView
		= QUICInitialHeaderView::createFromPayload(payload.subspan());
	if (!initialHeaderView.has_value()) {
		return std::nullopt;
	}

	return headerData;
}


} // namespace ipxp
