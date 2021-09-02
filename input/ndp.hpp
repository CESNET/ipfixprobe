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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef IPXP_INPUT_NDP_HPP
#define IPXP_INPUT_NDP_HPP

#include <ndpreader.hpp>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

class NdpOptParser : public OptionsParser
{
public:
   std::string m_dev;
   uint64_t m_id;

   NdpOptParser() : OptionsParser("ndp", "Input plugin for reading packets from a ndp interface"), m_dev(""), m_id(0)
   {
      register_option("d", "dev", "PATH", "Path to a device file", [this](const char *arg){m_dev = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("I", "id", "NUM", "Link identifier number",
         [this](const char *arg){try {m_id = str2num<decltype(m_id)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
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

   void init_ifc(const std::string &interface);
};

void packet_ndp_handler(Packet *pkt, const struct ndp_packet *ndp_packet, const struct ndp_header *ndp_header);

}
#endif /* IPXP_INPUT_NDP_HPP */
