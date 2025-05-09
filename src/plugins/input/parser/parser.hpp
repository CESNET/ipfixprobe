/**
 * \file parser.hpp
 * \brief Packet parser functions
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *
 *
 */

#ifndef IPXP_INPUT_PARSER_HPP
#define IPXP_INPUT_PARSER_HPP

#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/parser-stats.hpp>

#ifdef WITH_PCAP
#include <pcap/pcap.h>
#include <pcap/sll.h>
#endif /* WITH_PCAP */

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN*/
#endif

#ifndef ETH_P_TRILL
#define ETH_P_TRILL 0x22F3 /* TRILL protocol */
#endif

namespace ipxp {

typedef struct parser_opt_s {
	PacketBlock* pblock;
	bool packet_valid;
	bool parse_all;
	int datalink;
} parser_opt_t;

/**
 * \brief Parse one packet and update output metadata in `opt`, and statistics in `stats`.
 *
 * The function updates the metadata (using `opt->pblock->cnt` index) when the
 * packet is successfully parsed.  On error, the packet metadata at
 * `opt->pblock->cnt` index are invalid and the index points to the same place.
 * The caller must ensure `opt->pblock->size` is higher the `opt->pblock->cnt`;
 * this is checked and in case of no free space, `parse_packet()` returns
 * without any action.

 * \param [out] opt Pointer to the structure with an output list of parsed packet metadata.
 * \param [out] stats Structure with the ipfixprobe statistics counters.
 * \param [in] ts Timestamp of the current packet
 * \param [in] data  Input data, i.e., pointer to beginning of the packet header.
 * \param [in] len   Original size of the packet to process.
 * \param [in] caplen   Capture length - actual size of the packet, i.e., number of bytes that are
 available in data.
 */
void parse_packet(
	parser_opt_t* opt,
	ParserStats& stats,
	struct timeval ts,
	const uint8_t* data,
	uint16_t len,
	uint16_t caplen);

} // namespace ipxp
#endif /* IPXP_INPUT_PARSER_HPP */
