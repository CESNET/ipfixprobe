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
std::optional<std::size_t>
parseRetry(std::span<const std::byte> payload) noexcept
{
	/*const std::optional<VariableLengthInt> token
		= readQUICVariableLengthInt(payload);
	if (!token.has_value()) {
		return std::nullopt;
	}*/

	constexpr std::size_t IntegrityTagSize = 16;
	if (payload.size() < IntegrityTagSize) {
		return std::nullopt;
	}

	packetDirection = QUICDirection::SERVER_TO_CLIENT;
	packetTypesCumulative.bits.retry = true;

	return IntegrityTagSize;
}

constexpr static
std::optional<uint16_t> getServerPortFromInitialHeader(
	const std::optional<QUICInitialHeaderView>& initialHeaderView,
	const uint16_t srcPort,
	const uint16_t dstPort) noexcept
{
	if (!initialHeaderView.has_value()) {
		return std::nullopt;
	}
	if (!initialHeaderView->tlsHandshake.has_value()) {
		return std::nullopt;
	}

	

	return std::nullopt;
}

constexpr static
std::optional<uint16_t> getServerPort(
    const uint16_t srcPort, 
    const uint16_t dstPort,
	const std::optional<QUICInitialHeaderView>& initialHeaderView,
    const PacketType packetType) noexcept
{
	switch (packetType) {
	case PacketType::INITIAL:
		if (!initialHeaderView.has_value() || 
			!initialHeaderView->tlsHandshake.has_value()) {
			return std::nullopt;
		}

        switch (initialHeaderView->tlsHandshake->type)
        {
        case TLSHandshake::Type::CLIENT_HELLO:
            return dstPort;
        case TLSHandshake::Type::SERVER_HELLO:
            return srcPort;
        default:
		    // e.g. ACKs do not reveal direction
            return std::nullopt;
        }
	case PacketType::VERSION_NEGOTIATION: [[fallthrough]]
	case PacketType::RETRY:
		return srcPort;
	case PacketType::ZERO_RTT:
		return dstPort;
	case PacketType::HANDSHAKE:
		// Does not reveal the direction
		return std::nullopt;
	}

	return std::nullopt;
}

constexpr
std::optional<std::size_t> QUICParser::parseZeroRTT(
	std::span<const std::byte> payload) noexcept
{
	const std::optional<VariableLengthInt> restPayloadLength
		= readQUICVariableLengthInt(payload);
	if (!restPayloadLength.has_value()) {
		return std::nullopt;
	}

	if (m_zeroRTTPackets != std::numeric_limits<uint8_t>::max()) {
		m_zeroRTTPackets++;
	}

	packetTypesCumulative.bits.zeroRTT = true;
	packetDirection = QUICDirection::CLIENT_TO_SERVER;

	return restPayloadLength->value + restPayloadLength->length;
}

constexpr
std::optional<std::size_t> QUICParser::parseHandshake(
	std::span<const std::byte> payload) noexcept
{
	const std::optional<VariableLengthInt> restPayloadLength
		= readQUICVariableLengthInt(payload);
	if (!restPayloadLength.has_value()) {
		return std::nullopt;
	}

	if (restPayloadLength->value > MAX_PAYLOAD_BUFFER_SIZE) {
		return false;
	}

	packetTypesCumulative.bits.handshake = true;

	return restPayloadLength->value + restPayloadLength->length;
}

constexpr
std::optional<std::size_t> QUICParser::parseInitial(
	std::span<const std::byte> payload,
	std::span<const uint8_t> currentDCID,
	std::span<const uint8_t> previousDCID,
	const std::byte headerForm,
	std::span<const std::byte> salt,
	const uint16_t srcPort,
	const uint16_t dstPort) noexcept
{
	initialHeaderView = QUICInitialHeaderView::createFrom(currentDCID);
	if (!initialHeaderView.has_value()) {
		initialHeaderView = QUICInitialHeaderView::createFrom(previousDCID);
		if (!initialHeaderView.has_value()) {
			return std::nullopt;
		}
	}

	packetTypesCumulative.bits.initial = true;

	if (initialHeaderView->tlsHandshake->type == TLSHandshake::Type::SERVER_HELLO) {
		packetDirection = QUICDirection::SERVER_TO_CLIENT;
	}
	if (initialHeaderView->tlsHandshake->type == TLSHandshake::Type::CLIENT_HELLO) {
		packetDirection = QUICDirection::CLIENT_TO_SERVER;
	}

	return initialHeaderView->???;
}

bool QUICParser::parse(
	std::span<const std::byte> payload,
	const uint16_t srcPort,
	const uint16_t dstPort) noexcept
{
	// Handle coalesced packets
	// 7 because (1B QUIC LH, 4B Version, 1 B SCID LEN, 1B DCID LEN)
	constexpr std::size_t MIN_PACKET_SIZE = 8;
	for (std::optional<std::size_t> secondaryHeaderSize = std::nullopt;
		payload.size() >= MIN_PACKET_SIZE;
		payload = payload.subspan(*secondaryHeaderSize)) {

		// TODO CHECK IF SUBSPAN NOT STARTS AFTER SPAN END
		const std::optional<QUICHeaderView> headerView
			= QUICHeaderView::createFrom(payload.subspan(offset));
		if (!headerView.has_value()) {
			break;
		}
		payload = payload.subspan(headerView->getLength());

		packetType = headerView->getPacketType();
		switch (packetType) {
		case QUICHeaderView::PacketType::ZERO_RTT: {
			secondaryHeaderSize = parseZeroRTT(...);
			break;
		}
		case QUICHeaderView::PacketType::HANDSHAKE: {
			secondaryHeaderSize = parseHandshake(...);
			break;
		}
		case QUICHeaderView::PacketType::INITIAL: {
			secondaryHeaderSize = parseInitial(...);
			break;
		}
		case QUICHeaderView::PacketType::RETRY: {
			secondaryHeaderSize = parseRetry(payload);
			return true; // ??????????
			break;
		}
		case QUICHeaderView::PacketType::VERSION_NEGOTIATION: {
			packetDirection = QUICDirection::SERVER_TO_CLIENT;
			packetTypesCumulative.bits.versionNegotiation = true;
			return true; // ??????????
			break;
		}
		}

		if (!headerSize.has_value()) {
			return false;
		}

		/*if (packetType == QUICHeaderView::PacketType::RETRY) {
			return true;
		}*/
	}

	// Update packet type to most specific, i.e., Initial
	if (packets & F_INITIAL) {
		packet_type = INITIAL;
	}

	return true;
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
