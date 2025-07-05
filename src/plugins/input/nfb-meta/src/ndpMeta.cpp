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

#include "ndpMeta.hpp"

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

#include "ipfixprobe/packet.hpp"
#include "ipfixprobe/plugin.hpp"
#include "parser.hpp"
#include <ipfixprobe/cttmeta.hpp>

namespace ipxp {

static const PluginManifest ndpMetadataPluginManifest = {
   .name = "ndp-meta",
   .description = "Ndp input plugin for reading packets from network interface with metadata.",
   .pluginVersion = "1.0.0",
   .apiVersion = "1.0.0",
   .usage =
      []() {
         NdpMetaOptParser parser;
         parser.usage(std::cout);
      },
};

telemetry::Dict NdpMetadataPacketReader::get_queue_telemetry()
{
   telemetry::Dict dict = NdpPacketReaderCore::get_queue_telemetry();
   dict["bad_metadata"] = m_ctt_stats.bad_metadata;
   dict["ctt_unknown_packet_type"] = m_ctt_stats.ctt_unknown_packet_type;
   return dict;
}

NdpMetadataPacketReader::NdpMetadataPacketReader(const std::string& params)
{
	init(params.c_str());
}

void NdpMetadataPacketReader::init(const char *params)
{
   NdpMetaOptParser parser;
   try {
      parser.parse(params);
   } catch (const std::exception &e) {
      throw std::runtime_error("NDP metadata plugin: " + std::string(e.what()));
   }
   if (parser.m_dev.empty()) {
      throw PluginError("specify device path");
   }

   init_ifc(parser.m_dev);
   m_device = parser.m_dev;
   if (parser.m_metadata != "ctt") {
      throw PluginError("Only ctt metadata are supported");
   }
}


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

InputPlugin::Result NdpMetadataPacketReader::get(PacketBlock &packets)
{
   const auto parsing_callback = [this](parser_opt_t *opt, ParserStats& stats, struct timeval ts, const ndp_packet* packet){
      switch (packet->flags)
      {
      case MessageType::FLOW_EXPORT:{
         try_to_add_external_export_packet(*opt, packet->data, packet->data_length);
         break;
      }
      case MessageType::FRAME_AND_FULL_METADATA:{
         CttMetadata metadata = CttMetadata::parse(packet->header, packet->header_length);
         if (metadata.flow_hash == 0) {
            m_ctt_stats.bad_metadata++;
         }
         size_t count = opt->pblock->cnt;
         parse_packet(opt, stats, ts, packet->data, packet->data_length, packet->data_length);
         if (opt->pblock->cnt != count && metadata.flow_hash != 0) {
            opt->pblock->pkts[opt->pblock->cnt - 1].cttmeta = metadata;
         }
         break;
      }
      default:{
         m_ctt_stats.ctt_unknown_packet_type++;
         break;
      }
      }
   };
   return NdpPacketReaderCore::getBurst(packets, parsing_callback);
}

static const PluginRegistrar<NdpMetadataPacketReader, InputPluginFactory> ndpRegistrar(ndpMetadataPluginManifest);


} // namespace ipxp
