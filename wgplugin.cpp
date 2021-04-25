/**
 * \file wgplugin.cpp
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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
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

#include <iostream>
#include <cstring>

#include "wgplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define WG_UNIREC_TEMPLATE "WG_SRC_PEER,WG_DST_PEER"

UR_FIELDS (
   uint32 WG_SRC_PEER,
   uint32 WG_DST_PEER
)

WGPlugin::WGPlugin(const options_t &module_options)
{
   flow_flush = false;
   print_stats = module_options.print_stats;
   total = 0;
   identified = 0;
}

WGPlugin::WGPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   flow_flush = false;
   print_stats = module_options.print_stats;
   total = 0;
   identified = 0;
}

int WGPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.ip_proto == IPPROTO_UDP) {
      add_ext_wg(pkt.payload, pkt.payload_length, pkt.source_pkt, rec);
   }

   return 0;
}

int WGPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtWG *vpn_data = (RecordExtWG *) rec.getExtension(wg);
   if (vpn_data != NULL) {
      parse_wg(pkt.payload, pkt.payload_length, pkt.source_pkt, vpn_data);

      if (flow_flush) {
         flow_flush = false;
         return FLOW_FLUSH_WITH_REINSERT;
      }
   }

   return 0;
}


void WGPlugin::pre_export(Flow &rec)
{
}

void WGPlugin::finish()
{
   if (print_stats) {
      cout << "WG plugin stats:" << endl;
      cout << "   Identified WG packets: " << identified << endl;
      cout << "   Total packets processed: " << total << endl;
   }
}

const char *ipfix_wg_template[] = {
   IPFIX_WG_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **WGPlugin::get_ipfix_string()
{
   return ipfix_wg_template;
}

string WGPlugin::get_unirec_field_string()
{
   return WG_UNIREC_TEMPLATE;
}

bool WGPlugin::include_basic_flow_fields()
{
   return true;
}

bool WGPlugin::parse_wg(const char *data, unsigned int payload_len, bool source_pkt, RecordExtWG *ext)
{
   uint32_t cmp_peer;
   uint32_t cmp_new_peer;

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


   // TODO: more properties need to be parsed
   if (pkt_type == WG_PACKETTYPE_INIT_TO_RESP) {
      if (payload_len != WG_PACKETLEN_INIT_TO_RESP) {
         return false;
      }
      
      // compare the current dst_peer and see if it matches the original source.
      // If not, the flow flush may be needed to create a new flow.
      cmp_peer = source_pkt ? ext->src_peer : ext->dst_peer;
      memcpy(&cmp_new_peer, (data+4), sizeof(uint32_t));
      
      // cerr << "handshake init: new sender " << cmp_new_peer << ", old sender " << cmp_peer << endl;
      if (cmp_peer != 0 && cmp_peer != cmp_new_peer) {
         cerr << "new flow" << endl;
         flow_flush = true;
         return false;
      }

      memcpy(source_pkt ? &(ext->src_peer) : &(ext->dst_peer), (data+4), sizeof(uint32_t));
   } else if (pkt_type == WG_PACKETTYPE_RESP_TO_INIT) {
      if (payload_len != WG_PACKETLEN_RESP_TO_INIT) {
         return false;
      }

      memcpy(&(ext->src_peer), (data+4), sizeof(uint32_t));
      memcpy(&(ext->dst_peer), (data+8), sizeof(uint32_t));
      
      // let's swap for the opposite direction
      if (! source_pkt) {
         swap(ext->src_peer, ext->dst_peer);
      }
   } else if (pkt_type == WG_PACKETTYPE_COOKIE_REPLY) {
      if (payload_len != WG_PACKETLEN_COOKIE_REPLY) {
         return false;
      }

      memcpy(source_pkt ? &(ext->dst_peer) : &(ext->src_peer), (data+4), sizeof(uint32_t));
   } else if (pkt_type == WG_PACKETTYPE_TRANSPORT_DATA) {
      // Each packet of transport data is zero-padded to the multiple of 16 bytes in length.
      if (payload_len < WG_PACKETLEN_MIN_TRANSPORT_DATA || (payload_len % 16) != 0) {
         return false;
      }

      memcpy(source_pkt ? &(ext->dst_peer) : &(ext->src_peer), (data+4), sizeof(uint32_t));
   }

   // TODO see if this is really enough
   identified++;
   return true;
}

int WGPlugin::add_ext_wg(const char *data, unsigned int payload_len, bool source_pkt, Flow &rec)
{
   RecordExtWG *ext = new RecordExtWG();
   // try to parse WireGuard packet
   if (!parse_wg(data, payload_len, source_pkt, ext)) {
      delete ext;
      return 0;
   }
   
   rec.addExtension(ext);
   return 0;
}

