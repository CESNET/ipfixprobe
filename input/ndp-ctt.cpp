/**
 * \file ndp-ctt.cpp
 * \brief Packet reader using NDP library for high speed capture with Connection Tracking Table.
 * \author Jaroslav Pesek <jaroslav.pesek@fit.cvut.cz>
 * \date 2024
 */
/*
 * Copyright (C) 2020-2024 CESNET
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

#include "ndp-ctt.hpp"
#include "parser.hpp"
#include <ctt.hpp>
#include <ctt_factory.hpp>
#include <nfb/nfb.h>

namespace ipxp {

telemetry::Content NdpCttPacketReader::get_queue_telemetry()
{
   telemetry::Dict dict;
   dict["received_packets"] = m_stats.receivedPackets;
   dict["received_bytes"] = m_stats.receivedBytes;
   return dict;
}

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("ndp-ctt", [](){return new NdpCttPacketReader();});
   register_plugin(&rec);
}

NdpCttPacketReader::NdpCttPacketReader()
{
}

NdpCttPacketReader::~NdpCttPacketReader()
{
   close();
}

void NdpCttPacketReader::init(const char *params)
{
    NdpCttOptParser parser;
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

void NdpCttPacketReader::init_ifc(const std::string &dev)
{
    _nfbDevice.reset(nfb_open(dev.c_str()));

    if (!_nfbDevice) {
        throw PluginError(dev + ": failed to open device"  );
    }
}

void NdpCttPacketReader::close()
{
}

InputPlugin::Result NdpCttPacketReader::get(PacketBlock &packets)
{
   parser_opt_t opt = {&packets, false, false, 0};
   struct ndp_packer *ndp_packet;
   struct timeval timestamp;
   size_t read_pkts = 0;
   int ret = -1;
   


    return opt.pblock->cnt ? Result::PARSED : Result::NOT_PARSED;
}




} // namespace ipxp



