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
 // QUICParser::quic_obtain_version

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
