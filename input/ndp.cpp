/**
 * \file ndp.cpp
 * \brief Packet reader using NDP library for high speed capture.
 * \author Tomas Benes <benesto@fit.cvut.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2020-2021 CESNET
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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/types.h>
#include <cstdint>
#include <cstddef>
#include <inttypes.h>

#include "ndp.hpp"
#include "ipfixprobe/packet.hpp"
#include "ipfixprobe/plugin.hpp"
#include "parser.hpp"

namespace ipxp {

uint64_t extract(const uint8_t* bitvec, size_t start_bit, size_t bit_length) {
   size_t start_byte = start_bit / 8;
   size_t end_bit = start_bit + bit_length;
   size_t end_byte = (end_bit + 7) / 8;
   uint64_t value = 0;
   for (size_t i = 0; i < end_byte - start_byte; ++i) {
      value |= static_cast<uint64_t>(bitvec[start_byte + i]) << (8 * i);
   }
   value >>= (start_bit % 8);
   uint64_t mask = (bit_length == 64) ? ~0ULL : ((1ULL << bit_length) - 1);
   return value & mask;
}

telemetry::Content NdpPacketReader::get_queue_telemetry()
{
   telemetry::Dict dict;
   dict["received_packets"] = m_stats.receivedPackets;
   dict["received_bytes"] = m_stats.receivedBytes;
   return dict;
}

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("ndp", [](){return new NdpPacketReader();});
   register_plugin(&rec);
}

NdpPacketReader::NdpPacketReader()
{
}

NdpPacketReader::~NdpPacketReader()
{
   close();
}

void NdpPacketReader::init(const char *params)
{
   NdpOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   if (parser.m_dev.empty()) {
      throw PluginError("specify device path");
   }
   if (parser.m_metadata == "ctt") {
      m_ctt_metadata = true;
   }
   init_ifc(parser.m_dev);
}

void NdpPacketReader::close()
{
   ndpReader.close();
}

void NdpPacketReader::init_ifc(const std::string &dev)
{
   if (ndpReader.init_interface(dev) != 0) {
      throw PluginError(ndpReader.error_msg);
   }
}

void NdpPacketReader::parse_ctt_metadata(const ndp_packet *ndp_packet, Metadata_CTT &ctt)
{
   if (ndp_packet->header_length != 32) {
      throw PluginError("Metadata bad length, cannot parse, length: " + std::to_string(ndp_packet->header_length));
   }
   const uint8_t *metadata = ndp_packet->header;

   ctt.ts.tv_usec      = extract(metadata, 0,   32);
   ctt.ts.tv_sec       = extract(metadata, 32,  32);
   ctt.vlan_tci        = extract(metadata, 64,  16);
   ctt.vlan_vld        = extract(metadata, 80,  1);
   ctt.vlan_stripped   = extract(metadata, 81,  1);
   ctt.ip_csum_status  = extract(metadata, 82,  2);
   ctt.l4_csum_status  = extract(metadata, 84,  2);
   ctt.parser_status   = extract(metadata, 86,  2);
   ctt.ifc             = extract(metadata, 88,  8);
   ctt.filter_bitmap   = extract(metadata, 96,  16);
   ctt.ctt_export_trig = extract(metadata, 112, 1);
   ctt.ctt_rec_matched = extract(metadata, 113, 1);
   ctt.ctt_rec_created = extract(metadata, 114, 1);
   ctt.ctt_rec_deleted = extract(metadata, 115, 1);
   ctt.flow_hash       = extract(metadata, 128, 64);
   ctt.l2_len          = extract(metadata, 192, 7);
   ctt.l3_len          = extract(metadata, 199, 9);
   ctt.l4_len          = extract(metadata, 208, 8);
   ctt.l2_ptype        = extract(metadata, 216, 4);
   ctt.l3_ptype        = extract(metadata, 220, 4);
   ctt.l4_ptype        = extract(metadata, 224, 4);

   return;
}

InputPlugin::Result NdpPacketReader::get(PacketBlock &packets)
{
   parser_opt_t opt = {&packets, false, false, 0};
   struct ndp_packet *ndp_packet;
   struct timeval timestamp;
   size_t read_pkts = 0;
   int ret = -1;

   packets.cnt = 0;
   for (unsigned i = 0; i < packets.size; i++) {
      ret = ndpReader.get_pkt(&ndp_packet, &timestamp);
      if (ret == 0) {
         if (opt.pblock->cnt) {
            break;
         }
         return Result::TIMEOUT;
      } else if (ret < 0) {
         // Error occured.
         throw PluginError(ndpReader.error_msg);
      }
      read_pkts++;
      if (m_ctt_metadata) {
         Metadata_CTT ctt;
         parse_ctt_metadata(ndp_packet, ctt);
         parse_packet(&opt, m_parser_stats, timestamp, ndp_packet->data, ndp_packet->data_length, ndp_packet->data_length);

         Packet *pkt = &opt.pblock->pkts[opt.pblock->cnt - 1];

         // verify metadata with original parser
         if(ctt.l2_len + ctt.l3_len + ctt.l4_len != pkt->packet_len - pkt->payload_len) {
            printf("Error: ctt.l2_len (%d) + ctt.l3_len (%d) + ctt.l4_len (%d) != pkt->packet_len (%d) - pkt->payload_len (%d)\n", ctt.l2_len, ctt.l3_len, ctt.l4_len, pkt->packet_len, pkt->payload_len);
         }
         if(pkt->ip_proto == IPPROTO_TCP) {
            if(ctt.l4_ptype != 0x1) {
               printf("Error: ctt.l4_ptype (%d) != 0x1 but protocol is TCP (%d)\n", ctt.l4_ptype, pkt->ip_proto);
            }
         }
         if(pkt->ip_proto == IPPROTO_UDP) {
            if(ctt.l4_ptype != 0x2) {
               printf("Error: ctt.l4_ptype (%d) != 0x2 but protocol is UDP (%d)\n", ctt.l4_ptype, pkt->ip_proto);
            }
         }
      } else {
         parse_packet(&opt, m_parser_stats, timestamp, ndp_packet->data, ndp_packet->data_length, ndp_packet->data_length);
      }
   }

   m_seen += read_pkts;
   m_parsed += opt.pblock->cnt;

   m_stats.receivedPackets += read_pkts;
   m_stats.receivedBytes += packets.bytes;

   return opt.pblock->cnt ? Result::PARSED : Result::NOT_PARSED;
}

void NdpPacketReader::configure_telemetry_dirs(
   std::shared_ptr<telemetry::Directory> plugin_dir, 
   std::shared_ptr<telemetry::Directory> queues_dir)
{
   telemetry::FileOps statsOps = {[&]() { return get_queue_telemetry(); }, nullptr};
   register_file(queues_dir, "input-stats", statsOps);
}

}
