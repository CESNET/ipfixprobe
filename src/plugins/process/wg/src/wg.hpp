/**
 * @file
 * @brief Plugin for parsing wg traffic.
 * @author Pavel Valach <valacpav@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstring>
#include <sstream>
#include <string>

#include <endian.h>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>

namespace ipxp {

/**
 * \brief WireGuard packet types.
 */
#define WG_PACKETTYPE_INIT_TO_RESP 0x01 /**< Initiator to Responder message **/
#define WG_PACKETTYPE_RESP_TO_INIT 0x02 /**< Responder to Initiator message **/
#define WG_PACKETTYPE_COOKIE_REPLY 0x03 /**< Cookie Reply (under load) message **/
#define WG_PACKETTYPE_TRANSPORT_DATA 0x04 /**< Transport Data message **/

/**
 * \brief WireGuard UDP payload (minimum) lengths.
 */
#define WG_PACKETLEN_INIT_TO_RESP 148
#define WG_PACKETLEN_RESP_TO_INIT 92
#define WG_PACKETLEN_COOKIE_REPLY 64
#define WG_PACKETLEN_MIN_TRANSPORT_DATA 32

#define WG_UNIREC_TEMPLATE "WG_CONF_LEVEL,WG_SRC_PEER,WG_DST_PEER"

UR_FIELDS(uint8 WG_CONF_LEVEL, uint32 WG_SRC_PEER, uint32 WG_DST_PEER)

/**
 * \brief Flow record extension header for storing parsed WG packets.
 */
struct RecordExtWG : public RecordExt {
	uint8_t possible_wg;
	uint32_t src_peer;
	uint32_t dst_peer;

	RecordExtWG(int pluginID)
		: RecordExt(pluginID)
	{
		possible_wg = 0;
		src_peer = 0;
		dst_peer = 0;
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_WG_CONF_LEVEL, possible_wg);
		ur_set(tmplt, record, F_WG_SRC_PEER, src_peer);
		ur_set(tmplt, record, F_WG_DST_PEER, dst_peer);
	}

	const char* get_unirec_tmplt() const { return WG_UNIREC_TEMPLATE; }
#endif

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		int requiredLen = 0;

		requiredLen += sizeof(possible_wg); // WG_CONF_LEVEL
		requiredLen += sizeof(src_peer); // WG_SRC_PEER
		requiredLen += sizeof(dst_peer); // WG_DST_PEER

		if (requiredLen > size) {
			return -1;
		}

		memcpy(buffer, &possible_wg, sizeof(possible_wg));
		buffer += sizeof(possible_wg);
		uint32_t src_peer_be = htobe32(src_peer);
		memcpy(buffer, &src_peer_be, sizeof(src_peer));
		buffer += sizeof(src_peer);
		uint32_t dst_peer_be = htobe32(dst_peer);
		memcpy(buffer, &dst_peer_be, sizeof(dst_peer));
		buffer += sizeof(dst_peer);

		return requiredLen;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_tmplt[] = {IPFIX_WG_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfix_tmplt;
	}

	std::string get_text() const
	{
		std::ostringstream out;
		out << "wgconf=" << (uint16_t) possible_wg << ",wgsrcpeer=" << src_peer
			<< ",wgdstpeer=" << dst_peer;
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing WG packets.
 */
class WGPlugin : public ProcessPlugin {
public:
	WGPlugin(const std::string& params, int pluginID);
	~WGPlugin();
	void init(const char* params);
	void close();
	OptionsParser* get_parser() const { return new OptionsParser("wg", "Parse WireGuard traffic"); }
	std::string get_name() const { return "wg"; }
	RecordExt* get_ext() const { return new RecordExtWG(m_pluginID); }
	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt);
	int pre_update(Flow& rec, Packet& pkt);
	void pre_export(Flow& rec);
	void finish(bool print_stats);

private:
	RecordExtWG* preallocated_record; /**< Preallocated instance of record to use */
	bool flow_flush; /**< Instructs the engine to create new flow, during pre_update. */
	uint32_t total; /**< Total number of processed packets. */
	uint32_t identified; /**< Total number of identified WireGuard packets. */

	bool parse_wg(const char* data, unsigned int payload_len, bool source_pkt, RecordExtWG* ext);
	int add_ext_wg(const char* data, unsigned int payload_len, bool source_pkt, Flow& rec);
};

} // namespace ipxp
