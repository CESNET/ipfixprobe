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
#include <config.h>

#include "ndp.hpp"
#include "ipfixprobe/packet.hpp"
#include "ipfixprobe/plugin.hpp"
#include "parser.hpp"

namespace ipxp {

telemetry::Content NdpPacketReader::get_queue_telemetry()
{
   telemetry::Dict dict;
   dict["received_packets"] = m_stats.receivedPackets;
   dict["received_bytes"] = m_stats.receivedBytes;
   dict["bad_metadata"] = m_stats.bad_metadata;
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
   m_device = parser.m_dev;
}

void NdpPacketReader::close()
{
   ndpReader.close();
}

#ifdef WITH_CTT
std::pair<std::string, unsigned> NdpPacketReader::get_ctt_config() const
{
   std::string dev = m_device;
   int channel_id = 0;
   std::size_t delimiter_found = m_device.find_last_of(":");
   if (delimiter_found != std::string::npos) {
      std::string channel_str = m_device.substr(delimiter_found + 1);
      dev = m_device.substr(0, delimiter_found);
      channel_id = std::stoi(channel_str);
   }
   return std::make_pair(dev, channel_id);
}
#endif /* WITH_CTT */

void NdpPacketReader::init_ifc(const std::string &dev)
{
   if (ndpReader.init_interface(dev) != 0) {
      throw PluginError(ndpReader.error_msg);
   }
}

#ifdef WITH_CTT

static bool try_to_add_external_export_packet(parser_opt_t& opt, const uint8_t* packet_data, size_t length) noexcept
{
   if (opt.pblock->cnt >= opt.pblock->size) {
      return false;
   }
   opt.pblock->pkts[opt.pblock->cnt].packet = packet_data;
   opt.pblock->pkts[opt.pblock->cnt].payload = packet_data;
   opt.pblock->pkts[opt.pblock->cnt].packet_len = length;
   opt.pblock->pkts[opt.pblock->cnt].packet_len_wire = length;
   opt.pblock->pkts[opt.pblock->cnt].payload_len = length;
   opt.pblock->pkts[opt.pblock->cnt].external_export = true;
   opt.packet_valid = true;
   opt.pblock->cnt++;
   opt.pblock->bytes += length;
   return true;
}

#endif /* WITH_CTT */

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
#ifdef WITH_CTT
      if (m_ctt_metadata) {
         if (std::optional<CttMetadata> metadata = CttMetadata::parse(ndp_packet->header, ndp_packet->header_length);
            metadata.has_value() && parse_packet_ctt_metadata(&opt, m_parser_stats,
               *metadata, ndp_packet->data, ndp_packet->data_length, ndp_packet->data_length) != -1) {
            continue;
         }
         if (ndp_packet->flags == MessageType::FLOW_EXPORT && try_to_add_external_export_packet(opt, ndp_packet->data, ndp_packet->data_length)) {
            continue;
         }
         m_stats.bad_metadata++;
      }
#endif /* WITH_CTT */
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
