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

#include <cstdio>
#include <cstring>
#include <iostream>

#include "ndp.hpp"
#include "parser.hpp"

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("ndp", [](){return new NdpPacketReader();});
   register_plugin(&rec);
}

void packet_ndp_handler(parser_opt_t *opt, const struct ndp_packet *ndp_packet, const struct ndp_header *ndp_header)
{
   struct timeval ts;
   ts.tv_sec = le32toh(ndp_header->timestamp_sec);
   ts.tv_usec = le32toh(ndp_header->timestamp_nsec) / 1000;

   parse_packet(opt, ts, ndp_packet->data, ndp_packet->data_length, ndp_packet->data_length);
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

InputPlugin::Result NdpPacketReader::get(PacketBlock &packets)
{
   parser_opt_t opt = {&packets, false, false, 0};
   struct ndp_packet *ndp_packet;
   struct ndp_header *ndp_header;
   size_t read_pkts = 0;
   int ret = -1;

   packets.cnt = 0;
   for (unsigned i = 0; i < packets.size; i++) {
      ret = ndpReader.get_pkt(&ndp_packet, &ndp_header);
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
      packet_ndp_handler(&opt, ndp_packet, ndp_header);
   }

   m_seen += read_pkts;
   m_parsed += opt.pblock->cnt;
   return opt.pblock->cnt ? Result::PARSED : Result::NOT_PARSED;
}

}
