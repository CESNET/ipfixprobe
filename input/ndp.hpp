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

#ifndef IPXP_INPUT_NDP_HPP
#define IPXP_INPUT_NDP_HPP

#include <ndpreader.hpp>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>
#include <ipfixprobe/output.hpp>

namespace ipxp {

class NdpOptParser : public OptionsParser
{
public:
   std::string m_dev;
   uint64_t m_id;
   uint32_t m_dir;

   NdpOptParser() : OptionsParser("ndp", "Input plugin for reading packets from a ndp device"), m_dev(""),
      m_id(DEFAULT_EXPORTER_ID)
   {
      register_option("d", "dev", "PATH", "Path to a device file", [this](const char *arg){m_dev = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("I", "id", "NUM", "Exporter identification",
         [this](const char *arg){try {m_id = str2num<decltype(m_id)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("d", "dir", "NUM", "Dir bit field value",
         [this](const char *arg){try {m_dir = str2num<decltype(m_dir)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
   }
};

class NdpPacketReader : public InputPlugin
{
public:
   NdpPacketReader();
   ~NdpPacketReader();

   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new NdpOptParser(); }
   std::string get_name() const { return "ndp"; }
   InputPlugin::Result get(PacketBlock &packets);

private:
   NdpReader ndpReader;

   uint64_t m_id;
   uint32_t m_dir;

   void init_ifc(const std::string &dev);
};

void packet_ndp_handler(Packet *pkt, const struct ndp_packet *ndp_packet, const struct ndp_header *ndp_header);

}
#endif /* IPXP_INPUT_NDP_HPP */
