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

#include "ndp.hpp"
 
#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/types.h>
#include <cstdint>
#include <cstddef>
#include <inttypes.h>

#include "ipfixprobe/packet.hpp"
#include "ipfixprobe/plugin.hpp"
#include "parser.hpp"

namespace ipxp {

static const PluginManifest ndpPluginManifest = {
   .name = "ndp",
   .description = "Ndp input plugin for reading packets from network interface or ndp file.",
   .pluginVersion = "1.0.0",
   .apiVersion = "1.0.0",
   .usage =
      []() {
         NdpOptParser parser;
         parser.usage(std::cout);
      },
};

NdpPacketReader::NdpPacketReader(const std::string& params)
{
	init(params.c_str());
}

std::optional<CttConfig> NdpPacketReader::get_ctt_config() const
{
   return std::nullopt;
}

InputPlugin::Result NdpPacketReader::get(PacketBlock &packets)
{
   constexpr auto parsing_callback = [](parser_opt_t *opt, ParserStats& stats, struct timeval ts, const ndp_packet* packet){
      parse_packet(opt, stats, ts, packet->data, packet->data_length, packet->data_length);
   };
   return NdpPacketReaderCore::getBurst(packets, parsing_callback);
}

static const PluginRegistrar<NdpPacketReader, InputPluginFactory> ndpRegistrar(ndpPluginManifest);

}
