/**
 * @file
 * @brief Plugin for enriching flows for tls data.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>
#include <ipfixprobe/utils.hpp>
#include <tlsParser/tls_parser.hpp>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#define BUFF_SIZE 255UL

namespace ipxp {
#define TLS_UNIREC_TEMPLATE "TLS_SNI,TLS_JA3,TLS_JA4,TLS_ALPN,TLS_VERSION,TLS_EXT_TYPE,TLS_EXT_LEN"
UR_FIELDS(
	string TLS_SNI,
	string TLS_ALPN,
	uint16 TLS_VERSION,
	bytes TLS_JA3,
	string TLS_JA4,
	uint16* TLS_EXT_TYPE,
	uint16* TLS_EXT_LEN)

/**
 * \brief Flow record extension header for storing parsed HTTPS packets.
 */
// TODO fix IEs
#define TLS_EXT_TYPE_FIELD_ID 802
#define TLS_EXT_LEN_FIELD_ID 803
struct RecordExtTLS : public RecordExt {
	uint16_t version {0};
	char alpn[BUFF_SIZE] {};
	char sni[BUFF_SIZE] {};
	uint8_t ja3[16] {0};
	char ja4[36] {0};
	bool server_hello_parsed {false};
	std::array<uint16_t, MAX_TLS_EXT_LEN> extension_types {};
	std::array<uint16_t, MAX_TLS_EXT_LEN> extension_lengths {};
	uint32_t extensions_buffer_size {0};

	/**
	 * \brief Constructor.
	 */
	RecordExtTLS(int pluginID)
		: RecordExt(pluginID)
	{
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_TLS_VERSION, version);
		ur_set_string(tmplt, record, F_TLS_SNI, sni);
		ur_set_string(tmplt, record, F_TLS_ALPN, alpn);
		ur_set_var(tmplt, record, F_TLS_JA3, ja3, sizeof(ja3));
		ur_set_string(tmplt, record, F_TLS_JA4, ja4);
		ur_array_allocate(tmplt, record, F_QUIC_TLS_EXT_TYPE, extensions_buffer_size);
		for (auto i = 0U; i < extensions_buffer_size; i++) {
			ur_array_set(tmplt, record, F_TLS_EXT_TYPE, i, extension_types[i]);
		}
		ur_array_allocate(tmplt, record, F_TLS_EXT_LEN, extensions_buffer_size);
		for (auto i = 0U; i < extensions_buffer_size; i++) {
			ur_array_set(tmplt, record, F_TLS_EXT_LEN, i, extension_lengths[i]);
		}
	}

	const char* get_unirec_tmplt() const { return TLS_UNIREC_TEMPLATE; }

#endif // ifdef WITH_NEMEA

	int fill_ipfix(uint8_t* buffer, int size) override
	{
		IpfixBasicList basiclist;
		basiclist.hdrEnterpriseNum = IpfixBasicList::CesnetPEM;

		const size_t sni_len = strlen(sni);
		const size_t alpn_len = strlen(alpn);

		size_t pos = 0UL;

		const size_t len_tls_ext_type
			= sizeof(extension_types[0]) * (extensions_buffer_size) + basiclist.HeaderSize();
		const size_t len_tls_len
			= sizeof(extension_lengths[0]) * (extensions_buffer_size) + basiclist.HeaderSize();

		const size_t req_buff_len = (sni_len + 3) + (alpn_len + 3) + (2) + (16 + 3)
			+ (sizeof(ja4) + 3) + len_tls_ext_type
			+ len_tls_len; // (SNI) + (ALPN) + (VERSION) + (JA3) + (JA4)

		if (req_buff_len > (uint32_t) size) {
			return -1;
		}

		*(uint16_t*) buffer = ntohs(version);
		pos += 2;

		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) sni, sni_len);
		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) alpn, alpn_len);

		buffer[pos++] = 16;
		memcpy(buffer + pos, ja3, 16);
		pos += 16;

		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) ja4, sizeof(ja4));

		pos += basiclist.FillBuffer(
			buffer + pos,
			extension_types.data(),
			extensions_buffer_size,
			(uint16_t) TLS_EXT_TYPE_FIELD_ID);
		pos += basiclist.FillBuffer(
			buffer + pos,
			extension_lengths.data(),
			extensions_buffer_size,
			(uint16_t) TLS_EXT_LEN_FIELD_ID);
		return static_cast<int>(pos);
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_template[] = {IPFIX_TLS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfix_template;
	}

	std::string get_text() const override
	{
		std::ostringstream out;

		out << "tlssni=\"" << sni << "\""
			<< ",tlsalpn=\"" << alpn << "\""
			<< ",tlsversion=0x" << std::hex << std::setw(4) << std::setfill('0') << version
			<< ",tlsja3=";
		for (int i = 0; i < 16; i++) {
			out << std::hex << std::setw(2) << std::setfill('0') << (unsigned) ja3[i];
		}
		out << ",tlsexttype=(";
		for (auto i = 0U; i < extensions_buffer_size; i++) {
			out << std::dec << (uint16_t) extension_types[i];
			if (i != extensions_buffer_size - 1) {
				out << ",";
			}
		}
		out << "),tlsextlen=(";
		for (auto i = 0U; i < extensions_buffer_size; i++) {
			out << std::dec << (uint16_t) extension_lengths[i];
			if (i != extensions_buffer_size - 1U) {
				out << ",";
			}
		}
		out << ")";

		return out.str();
	}
};

#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2

/**
 * \brief Flow cache plugin for parsing HTTPS packets.
 */
class TLSPlugin : public ProcessPlugin {
public:
	TLSPlugin(const std::string& params, int pluginID);
	~TLSPlugin() override;
	void init(const char* params) override;
	void close() override;
	OptionsParser* get_parser() const override;

	std::string get_name() const override;

	RecordExtTLS* get_ext() const override;

	ProcessPlugin* copy();

	ProcessPlugin::FlowAction post_create(Flow& rec, const Packet& pkt) override;
	ProcessPlugin::FlowAction pre_update(Flow& rec, Packet& pkt) override;
	void finish(bool print_stats);

private:
	ProcessPlugin::FlowAction add_tls_record(Flow&, const Packet&);
	bool parse_tls(const uint8_t* data, uint16_t payload_len, RecordExtTLS* rec, uint8_t ip_proto);

	RecordExtTLS* ext_ptr {nullptr};
	TLSParser tls_parser {};
	uint32_t parsed_sni {0};
};

} // namespace ipxp
