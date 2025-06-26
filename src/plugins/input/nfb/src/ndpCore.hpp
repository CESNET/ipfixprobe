/**
 * \file ndp.hpp
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

#pragma once

#include <bits/types/struct_timeval.h>
#include "ndpReader.hpp"

#include <ipfixprobe/inputPlugin.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>
#include <ipfixprobe/cttmeta.hpp>
#include <ipfixprobe/cttConfig.hpp>
#include "parser.hpp"

namespace ipxp {

class NdpOptParser : public OptionsParser
{
public:
   std::string m_dev;
   uint64_t m_id;

   NdpOptParser() : OptionsParser("ndp", "Input plugin for reading packets from a ndp device"), m_dev(""), m_id(0)
   {
      register_option("d", "dev", "PATH", "Path to a device file", [this](const char *arg){m_dev = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("I", "id", "NUM", "Link identifier number",
         [this](const char *arg){try {m_id = str2num<decltype(m_id)>(arg);} catch(std::invalid_argument &e) {return false;} return true;}, OptionFlags::RequiredArgument);
   }
};

class NdpPacketReaderCore : public InputPlugin
{
public:
   NdpPacketReaderCore();
   ~NdpPacketReaderCore();

   void init(const char *params) override;
   void close();

   template<typename PacketParsingCallback>
   InputPlugin::Result getBurst(PacketBlock &packets, PacketParsingCallback& callback)
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
         callback(&opt, m_parser_stats, timestamp, ndp_packet);
      }

      m_seen += read_pkts;
      m_parsed += opt.pblock->cnt;

      m_stats.receivedPackets += read_pkts;
      m_stats.receivedBytes += packets.bytes;
      return opt.pblock->cnt ? Result::PARSED : Result::NOT_PARSED;
   }

   void configure_telemetry_dirs(
      std::shared_ptr<telemetry::Directory> plugin_dir, 
      std::shared_ptr<telemetry::Directory> queues_dir) override;

   virtual std::optional<CttConfig> get_ctt_config() const;
      
protected:
   struct RxStats {
        uint64_t receivedPackets;
        uint64_t receivedBytes;
   };

   virtual telemetry::Dict get_queue_telemetry();
   void init_ifc(const std::string &dev);

   NdpReader ndpReader;
   RxStats m_stats = {};
   std::string m_device;

};

}
