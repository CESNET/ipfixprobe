/**
 * \file wg.cpp
 * \brief Plugin for parsing wg traffic.
 * \author Pavel Valach <valacpav@fit.cvut.cz>
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
 *
 *
 */

#include <iostream>
#include <cstring>

#include "wg.hpp"

namespace ipxp {

int RecordExtWG::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("wg", [](){return new WGPlugin();});
   register_plugin(&rec);
   RecordExtWG::REGISTERED_ID = register_extension();
}

WGPlugin::WGPlugin() : preallocated_record(nullptr), flow_flush(false), total(0), identified(0)
{
}

WGPlugin::~WGPlugin()
{
   close();
}

void WGPlugin::init(const char *params)
{
}

void WGPlugin::close()
{
   if (preallocated_record != nullptr) {
      delete preallocated_record;
      preallocated_record = nullptr;
   }
}

ProcessPlugin *WGPlugin::copy()
{
   return new WGPlugin(*this);
}

int WGPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.ip_proto == IPPROTO_UDP) {
      add_ext_wg(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, pkt.source_pkt, rec);
   }

   return 0;
}

int WGPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtWG *vpn_data = (RecordExtWG *) rec.get_extension(RecordExtWG::REGISTERED_ID);
   if (vpn_data != nullptr && vpn_data->possible_wg) {
      bool res = parse_wg(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, pkt.source_pkt, vpn_data);
      // In case of new flow, flush
      if (flow_flush) {
         flow_flush = false;
         return FLOW_FLUSH_WITH_REINSERT;
      }
      // In other cases, when WG was not detected
      if (!res) {
         vpn_data->possible_wg = 0;
      }
   }

   return 0;
}

void WGPlugin::pre_export(Flow &rec)
{
}

void WGPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "WG plugin stats:" << std::endl;
      std::cout << "   Identified WG packets: " << identified << std::endl;
      std::cout << "   Total packets processed: " << total << std::endl;
   }
}

bool WGPlugin::parse_wg(const char *data, unsigned int payload_len, bool source_pkt, RecordExtWG *ext)
{
   uint32_t cmp_peer;
   uint32_t cmp_new_peer;

   static const char dns_query_mask [4] = {0x00, 0x01, 0x00, 0x00};

   total++;

   // The smallest message (according to specs) is the data message (0x04) with 16 header bytes
   // and 16 bytes of (empty) data authentication.
   // Anything below that is not a valid WireGuard message.
   if (payload_len < WG_PACKETLEN_MIN_TRANSPORT_DATA) {
      return false;
   }

   // Let's try to parse according to the first 4 bytes, and see if that is enough.
   // The first byte is 0x01-0x04, the following three bytes are reserved (0x00).
   uint8_t pkt_type = data[0];
   if (pkt_type < WG_PACKETTYPE_INIT_TO_RESP || pkt_type > WG_PACKETTYPE_TRANSPORT_DATA) {
      return false;
   }
   if (data[1] != 0x0 || data[2] != 0x0 || data[3] != 0x0) {
      return false;
   }

   // Next, check the packet contents based on the message type.
   switch (pkt_type) {
      case WG_PACKETTYPE_INIT_TO_RESP:
         if (payload_len != WG_PACKETLEN_INIT_TO_RESP) {
            return false;
         }

         // compare the current dst_peer and see if it matches the original source.
         // If not, the flow flush may be needed to create a new flow.
         cmp_peer = source_pkt ? ext->src_peer : ext->dst_peer;
         memcpy(&cmp_new_peer, (data + 4), sizeof(uint32_t));

         if (cmp_peer != 0 && cmp_peer != cmp_new_peer) {
            flow_flush = true;
            return false;
         }

         memcpy(source_pkt ? &(ext->src_peer) : &(ext->dst_peer), (data + 4), sizeof(uint32_t));
         break;

      case WG_PACKETTYPE_RESP_TO_INIT:
         if (payload_len != WG_PACKETLEN_RESP_TO_INIT) {
            return false;
         }

         memcpy(&(ext->src_peer), (data + 4), sizeof(uint32_t));
         memcpy(&(ext->dst_peer), (data + 8), sizeof(uint32_t));

         // let's swap for the opposite direction
         if (!source_pkt) {
            std::swap(ext->src_peer, ext->dst_peer);
         }
         break;

      case WG_PACKETTYPE_COOKIE_REPLY:
         if (payload_len != WG_PACKETLEN_COOKIE_REPLY) {
            return false;
         }

         memcpy(source_pkt ? &(ext->dst_peer) : &(ext->src_peer), (data + 4), sizeof(uint32_t));
         break;

      case WG_PACKETTYPE_TRANSPORT_DATA:
         // Each packet of transport data is zero-padded to the multiple of 16 bytes in length.
         if (payload_len < WG_PACKETLEN_MIN_TRANSPORT_DATA || (payload_len % 16) != 0) {
            return false;
         }

         memcpy(source_pkt ? &(ext->dst_peer) : &(ext->src_peer), (data + 4), sizeof(uint32_t));
         break;
   }

   // Possible misdetection
   // - DNS request
   //   Can happen when transaction ID is >= 1 and <= 4, the query is non-recursive
   //   and other flags are zeros, too.
   //   2B transaction ID, 2B flags, 2B questions count, 2B answers count
   if (!memcmp((data + 4), dns_query_mask, sizeof(dns_query_mask))) {
      ext->possible_wg = 1;
   } else {
      ext->possible_wg = 100;
   }
   identified++;
   return true;
}

int WGPlugin::add_ext_wg(const char *data, unsigned int payload_len, bool source_pkt, Flow &rec)
{
   if (preallocated_record == nullptr) {
      preallocated_record = new RecordExtWG();
   }
   // try to parse WireGuard packet
   if (!parse_wg(data, payload_len, source_pkt, preallocated_record)) {
      return 0;
   }

   rec.add_extension(preallocated_record);
   preallocated_record = nullptr;
   return 0;
}

}
