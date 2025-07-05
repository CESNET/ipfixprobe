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

#include "ndpCore.hpp"
#include "ipfixprobe/packet.hpp"
#include "ipfixprobe/plugin.hpp"

namespace ipxp {

telemetry::Dict NdpPacketReaderCore::get_queue_telemetry()
{
   telemetry::Dict dict;
   dict["received_packets"] = m_stats.receivedPackets;
   dict["received_bytes"] = m_stats.receivedBytes;
   return dict;
}

NdpPacketReaderCore::NdpPacketReaderCore()
{
}

NdpPacketReaderCore::~NdpPacketReaderCore()
{
   close();
}

void NdpPacketReaderCore::init(const char *params)
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
   m_device = parser.m_dev;
}

void NdpPacketReaderCore::close()
{
   ndpReader.close();
}


void NdpPacketReaderCore::init_ifc(const std::string &dev)
{
   if (ndpReader.init_interface(dev) != 0) {
      throw PluginError(ndpReader.error_msg);
   }
}


std::optional<CttConfig> NdpPacketReaderCore::get_ctt_config() const
{
   std::string dev = m_device;
   int channel_id = 0;
   std::size_t delimiter_found = m_device.find_last_of(":");
   if (delimiter_found != std::string::npos) {
      std::string channel_str = m_device.substr(delimiter_found + 1);
      dev = m_device.substr(0, delimiter_found);
      channel_id = std::stoi(channel_str);
   }
   return CttConfig{dev, channel_id};
}

void NdpPacketReaderCore::configure_telemetry_dirs(
   std::shared_ptr<telemetry::Directory> plugin_dir, 
   std::shared_ptr<telemetry::Directory> queues_dir)
{
   telemetry::FileOps statsOps = {[&]() -> telemetry::Content { return get_queue_telemetry(); }, nullptr};
   register_file(queues_dir, "input-stats", statsOps);
}

}
