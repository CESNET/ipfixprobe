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
#include <ipfixprobe/inputPlugin.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>
#include "../../nfb/src/ndpCore.hpp"

namespace ipxp {

class NdpMetaOptParser : public OptionsParser
{
public:
   std::string m_dev;
   uint64_t m_id;
   std::string m_metadata;

   NdpMetaOptParser() : OptionsParser("ndp-meta", "Input plugin for reading packets from a ndp device using metadata"), m_dev(""), m_id(0), m_metadata("")
   {
      register_option("d", "dev", "PATH", "Path to a device file", [this](const char *arg){m_dev = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("I", "id", "NUM", "Link identifier number",
         [this](const char *arg){try {m_id = str2num<decltype(m_id)>(arg);} catch(std::invalid_argument &e) {return false;} return true;}, OptionFlags::RequiredArgument);
      register_option("M", "meta", "Metadata type", "Choose metadata type if any", [this](const char *arg){m_metadata = arg; return true;}, OptionFlags::RequiredArgument);
   }
};

class NdpMetadataPacketReader : public NdpPacketReaderCore
{
public:
   NdpMetadataPacketReader(const std::string& params);
   void init(const char *params) override;
   OptionsParser *get_parser() const { return new NdpMetaOptParser(); }
   std::string get_name() const { return "ndp-meta"; }
   InputPlugin::Result get(PacketBlock &packets);

private:
   struct CttStats {
        uint64_t bad_metadata{0};
        uint64_t ctt_unknown_packet_type{0};
   };

   telemetry::Dict get_queue_telemetry() override;

   NdpReader ndpReader;
   CttStats m_ctt_stats = {};
};

}
