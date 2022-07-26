/**
 * \file stem.cpp
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

#include <config.h>
#include <string>

#include <packet-reader.h>

#include "stem.hpp"

namespace ipxp {

// Read only 1 packet into packet block
constexpr size_t STEM_PACKET_BLOCK_SIZE = 1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("stem", [](){return new StemPacketReader();});
   register_plugin(&rec);
}

StemPacketReader::StemPacketReader() : m_reader(nullptr)
{
}

StemPacketReader::~StemPacketReader()
{
   close();
}

void StemPacketReader::init(const char *params)
{
   StemOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   if (parser.m_dev.empty()) {
      throw PluginError("specify device path");
   }

   open_dev(parser.m_dev);
}

void StemPacketReader::close()
{
   if (m_reader != nullptr) {
      delete m_reader;
      m_reader = nullptr;
   }
}

void StemPacketReader::open_dev(const std::string &file)
{
   try {
      m_reader = new Stem::StemInterface<Stem::PcapReader>(file);
   } catch (Stem::Exceptions::Readers::ReaderSetupError &e) {
      throw PluginError(e.what());
   }
}

bool StemPacketReader::convert(Stem::StatisticsPacket &stem_pkt, Packet &pkt)
{
   Stem::StadeHardwareData hwdata = stem_pkt.hw_data();
   if (hwdata.size() > pkt.buffer_size) {
      return false;
   }

   pkt.ts = {hwdata.arrived_at.sec, hwdata.arrived_at.nsec / 1000};

   memset(pkt.dst_mac, 0, sizeof(pkt.dst_mac));
   memset(pkt.src_mac, 0, sizeof(pkt.src_mac));
   pkt.ethertype = 0;

   size_t vlan_cnt = (hwdata.vlan_0 ? 1 : 0) + (hwdata.vlan_1 ? 1 : 0);
   size_t ip_offset = 14 + vlan_cnt * 4;

   pkt.ip_len = hwdata.frame_len - ip_offset; // this should be done better
   pkt.ip_version = hwdata.ip_version; // Get ip version
   pkt.ip_ttl = 0;
   pkt.ip_proto = hwdata.protocol;
   pkt.ip_tos = 0;
   pkt.ip_flags = 0;
   if (pkt.ip_version == IP::v4) {
      pkt.src_ip.v4 = *reinterpret_cast<uint32_t*>(hwdata.src_ip.data());
      pkt.dst_ip.v4 = *reinterpret_cast<uint32_t*>(hwdata.dst_ip.data());
      pkt.ip_payload_len = pkt.ip_len - 20;
   } else {
      memcpy(pkt.src_ip.v6, reinterpret_cast<uint8_t*>(hwdata.src_ip.data()), 16);
      memcpy(pkt.dst_ip.v6, reinterpret_cast<uint8_t*>(hwdata.dst_ip.data()), 16);
      pkt.ip_payload_len = pkt.ip_len - 40;
   }

   pkt.src_port = ntohs(hwdata.src_port);
   pkt.dst_port = ntohs(hwdata.dst_port);
   pkt.tcp_flags = hwdata.l4_flags;
   pkt.tcp_window = 0;
   pkt.tcp_options = 0;
   pkt.tcp_mss = 0;
   pkt.tcp_seq = hwdata.tcp_seq;
   pkt.tcp_ack = hwdata.tcp_ack;

   auto &raw_hwdata = stem_pkt.serialized();
   uint16_t datalen = raw_hwdata->size();
   if (datalen > pkt.buffer_size) {
      datalen = pkt.buffer_size;
   }
   memcpy(pkt.buffer, raw_hwdata->data(), datalen);

   pkt.packet = pkt.buffer;
   pkt.packet_len = 0;
   pkt.packet_len_wire = hwdata.frame_len;

   pkt.custom = pkt.buffer;
   pkt.custom_len = hwdata.size();

   pkt.payload = pkt.buffer + hwdata.size();
   pkt.payload_len = datalen - hwdata.size();
   if (datalen < hwdata.size()) {
      pkt.payload_len = 0;
   }
   pkt.payload_len_wire = raw_hwdata->size() - hwdata.size();

   return true;
}

InputPlugin::Result StemPacketReader::get(PacketBlock &packets)
{
   packets.cnt = 0;
   packets.bytes = 0;
   while (packets.cnt < STEM_PACKET_BLOCK_SIZE) {
      try {
         auto pkt = m_reader->next_packet();
         if (!pkt.has_value()) {
            if (packets.cnt) {
               return Result::PARSED;
            }
            return Result::TIMEOUT;
         } else {
            Stem::StatisticsPacket spkt = std::move(pkt.value());
            bool status = convert(spkt, packets.pkts[packets.cnt]);
            packets.bytes += packets.pkts[packets.cnt].packet_len_wire;

            m_seen += 1;
            if (!status) {
               continue;
            }
            packets.cnt++;
            m_parsed += 1;
         }
      } catch (Stem::Exceptions::Readers::ReadError &e) {
         throw PluginError(e.what());
      }
   }

   return packets.cnt ? Result::PARSED : Result::NOT_PARSED;
 }

}
