/**
 * \file packet.hpp
 * \brief Structs/classes for communication between packet reader and flow cache
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef IPXP_PACKET_HPP
#define IPXP_PACKET_HPP

#include <stdint.h>
#include <stdlib.h>

#include <ipfixprobe/ipaddr.hpp>
#include <ipfixprobe/flowifc.hpp>

namespace ipxp {

/**
 * \brief Structure for storing parsed packet fields
 */
struct Packet : public Record {
   struct timeval ts;

   uint8_t     dst_mac[6];
   uint8_t     src_mac[6];
   uint16_t    ethertype;

   uint16_t    ip_len; /**< Length of IP header + its payload */
   uint16_t    ip_payload_len; /**< Length of IP payload */
   uint8_t     ip_version;
   uint8_t     ip_ttl;
   uint8_t     ip_proto;
   uint8_t     ip_tos;
   uint8_t     ip_flags;
   ipaddr_t    src_ip;
   ipaddr_t    dst_ip;

   uint16_t    src_port;
   uint16_t    dst_port;
   uint8_t     tcp_flags;
   uint16_t    tcp_window;
   uint64_t    tcp_options;
   uint32_t    tcp_mss;
   uint32_t    tcp_seq;
   uint32_t    tcp_ack;

   const uint8_t *packet; /**< Pointer to begin of packet, if available */
   uint16_t    packet_len; /**< Length of data in packet buffer, packet_len <= packet_len_wire */
   uint16_t    packet_len_wire; /**< Original packet length on wire */

   const uint8_t *payload; /**< Pointer to begin of payload, if available */
   uint16_t    payload_len; /**< Length of data in payload buffer, payload_len <= payload_len_wire */
   uint16_t    payload_len_wire; /**< Original payload length computed from headers */

   uint8_t     *custom; /**< Pointer to begin of custom data, if available */
   uint16_t    custom_len; /**< Length of data in custom buffer */

   // TODO REMOVE
   uint8_t     *buffer; /**< Buffer for packet, payload and custom data */
   uint16_t    buffer_size; /**< Size of buffer */

   bool        source_pkt; /**< Direction of packet from flow point of view */

   /**
    * \brief Constructor.
    */
   Packet() :
      ts({0}),
      dst_mac(), src_mac(), ethertype(0),
      ip_len(0), ip_payload_len(0), ip_version(0), ip_ttl(0),
      ip_proto(0), ip_tos(0), ip_flags(0), src_ip({0}), dst_ip({0}),
      src_port(0), dst_port(0), tcp_flags(0), tcp_window(0),
      tcp_options(0), tcp_mss(0), tcp_seq(0), tcp_ack(0),
      packet(nullptr), packet_len(0), packet_len_wire(0),
      payload(nullptr), payload_len(0), payload_len_wire(0),
      custom(nullptr), custom_len(0),
      buffer(nullptr), buffer_size(0),
      source_pkt(true)
   {
   }
};

struct PacketBlock {
   Packet *pkts;
   size_t cnt;
   size_t bytes;
   size_t size;

   PacketBlock(size_t pkts_size) :
      cnt(0), bytes(0), size(pkts_size)
   {
      pkts = new Packet[pkts_size];
   }

   ~PacketBlock()
   {
      delete[] pkts;
   }
};

}
#endif /* IPXP_PACKET_HPP */
