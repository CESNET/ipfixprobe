/**
 * \file stem.hpp
 * \brief Plugin for reading stem specific data from hw
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#ifndef IPXP_INPUT_STEM_HPP
#define IPXP_INPUT_STEM_HPP

#include <config.h>

#include <stem-interface.h>
#include <statistics-packet.h>
#include <pcap-reader.h>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

class StemOptParser : public OptionsParser
{
public:
   std::string m_dev;

   StemOptParser() : OptionsParser("stem", "Input plugin for reading packets using libstem"),
      m_dev("")
   {
      register_option("d", "dev", "PATH", "Path to a device file", [this](const char *arg){m_dev = arg; return true;}, OptionFlags::RequiredArgument);
   }
};

class StemPacketReader : public InputPlugin
{
public:
   StemPacketReader();
   ~StemPacketReader();

   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new StemOptParser(); }
   std::string get_name() const { return "stem"; }
   InputPlugin::Result get(PacketBlock &packets);

private:
   Stem::StemInterface<Stem::PcapReader> *m_reader;

   bool convert(Stem::StatisticsPacket &stem_pkt, Packet &pkt);
   void open_dev(const std::string &file);
};

}
#endif /* IPXP_INPUT_STEM_HPP */
