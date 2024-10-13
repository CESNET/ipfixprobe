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
#include <sys/types.h>
#include <cstdint>
#include <cstddef>
#include <inttypes.h>

#include "ndp.hpp"
#include "ipfixprobe/plugin.hpp"
#include "parser.hpp"

namespace ipxp {

template <typename T>
T extract(const uint8_t* metadata, size_t bit_position, size_t num_bits) {
    uint64_t result = 0;
    size_t bit_offset = bit_position % 8;
    size_t byte_index = bit_position / 8;
    size_t bits_extracted = 0;

    while (bits_extracted < num_bits) {
        uint8_t byte = metadata[byte_index++];
        uint8_t bits_in_this_byte = std::min(8 - bit_offset, num_bits - bits_extracted);

        uint8_t mask = ((1 << bits_in_this_byte) - 1) << (8 - bit_offset - bits_in_this_byte);
        uint8_t extracted_bits = (byte & mask) >> (8 - bit_offset - bits_in_this_byte);

        result = (result << bits_in_this_byte) | extracted_bits;

        bits_extracted += bits_in_this_byte;
        bit_offset = 0;
    }
    return static_cast<T>(result);
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

void NdpPacketReader::parse_ctt_metadata(const struct ndp_packet *ndp_packet)
{
   Metadata_CTT ctt;
   if (ndp_packet->header_length != 32) {
      throw PluginError("Metadata bad length, cannot parse, length: " + std::to_string(ndp_packet->header_length));
   }
   const uint8_t *metadata = ndp_packet->header;
   for (int i = 0; i < 32; i++) {
      printf("%02x ", metadata[i]);
   }
   printf("\n");

   uint32_t timestamp_nanosec = *((uint32_t*)metadata);
   uint32_t timestamp_sec = *((uint32_t*)metadata+1);
   timeval tv;
   tv.tv_sec = timestamp_sec;
   tv.tv_usec = timestamp_nanosec / 1000;

   ctt.vlan_tci         = extract<uint16_t>(metadata,  64,  16);
   ctt.vlan_vld         = extract<uint8_t>(metadata,   80,   1);
   ctt.vlan_stripped    = extract<uint8_t>(metadata,   81,   1);
   ctt.l3_csum_status   = extract<uint8_t>(metadata,   82,   2);
   ctt.l4_csum_status   = extract<uint8_t>(metadata,   84,   2);
   ctt.parser_status    = extract<uint8_t>(metadata,   86,   2);
   ctt.ifc              = extract<uint8_t>(metadata,   88,   8);
   ctt.filter_bitmap    = extract<uint16_t>(metadata,  96,  16);
   ctt.ctt_export_trig  = extract<uint8_t>(metadata,  112,   1);
   ctt.ctt_rec_matched  = extract<uint8_t>(metadata,  113,   1);
   ctt.ctt_rec_created  = extract<uint8_t>(metadata,  114,   1);
   ctt.ctt_rec_deleted  = extract<uint8_t>(metadata,  115,   1);
   ctt.flow_hash        = extract<uint64_t>(metadata, 128,  64);
   ctt.l2_len           = extract<uint16_t>(metadata, 192,   7);
   ctt.l3_len           = extract<uint16_t>(metadata, 199,   9);
   ctt.l4_len           = extract<uint8_t>(metadata,  208,   8);
   ctt.l2_ptype         = extract<uint8_t>(metadata,  216,   4);
   ctt.l3_ptype         = extract<uint8_t>(metadata,  220,   4);
   ctt.l4_ptype         = extract<uint8_t>(metadata,  224,   4);

   printf("Timestamp: %u.%u\n", timestamp_sec, timestamp_nanosec);
   printf("VLAN TCI: %" PRIu16 " (0x%" PRIx16 ")\n", ctt.vlan_tci, ctt.vlan_tci);
   printf("VLAN VLD: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.vlan_vld, ctt.vlan_vld);
   printf("VLAN STRIPPED: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.vlan_stripped, ctt.vlan_stripped);
   printf("L3 CSUM STATUS: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.l3_csum_status, ctt.l3_csum_status);
   printf("L4 CSUM STATUS: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.l4_csum_status, ctt.l4_csum_status);
   printf("PARSER STATUS: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.parser_status, ctt.parser_status);
   printf("IFC: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.ifc, ctt.ifc);
   printf("FILTER BITMAP: %" PRIu16 " (0x%" PRIx16 ")\n", ctt.filter_bitmap, ctt.filter_bitmap);
   printf("CTT EXPORT TRIG: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.ctt_export_trig, ctt.ctt_export_trig);
   printf("CTT REC MATCHED: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.ctt_rec_matched, ctt.ctt_rec_matched);
   printf("CTT REC CREATED: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.ctt_rec_created, ctt.ctt_rec_created);
   printf("CTT REC DELETED: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.ctt_rec_deleted, ctt.ctt_rec_deleted);
   printf("FLOW HASH: %" PRIu64 " (0x%" PRIx64 ")\n", ctt.flow_hash, ctt.flow_hash);
   printf("L2 LEN: %" PRIu16 " (0x%" PRIx16 ")\n", ctt.l2_len, ctt.l2_len);
   printf("L3 LEN: %" PRIu16 " (0x%" PRIx16 ")\n", ctt.l3_len, ctt.l3_len);
   printf("L4 LEN: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.l4_len, ctt.l4_len);
   printf("L2 PTYPE: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.l2_ptype, ctt.l2_ptype);
   printf("L3 PTYPE: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.l3_ptype, ctt.l3_ptype);
   printf("L4 PTYPE: %" PRIu8 " (0x%" PRIx8 ")\n", ctt.l4_ptype, ctt.l4_ptype);
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
         parse_ctt_metadata(ndp_packet);
      }
      parse_packet(&opt, m_parser_stats, timestamp, ndp_packet->data, ndp_packet->data_length, ndp_packet->data_length);
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
