/**
 * \file basicplusplugin.cpp
 * \brief Plugin for parsing basicplus traffic.
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

#include "basicplusplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define BASICPLUS_UNIREC_TEMPLATE \
   "IP_TTL,IP_TTL_REV,IP_FLG,IP_FLG_REV,TCP_WIN,TCP_WIN_REV,TCP_OPT,TCP_OPT_REV,TCP_MSS,TCP_MSS_REV,TCP_SYN_SIZE"

UR_FIELDS (
   uint8 IP_TTL,
   uint8 IP_TTL_REV,
   uint8 IP_FLG,
   uint8 IP_FLG_REV,
   uint16 TCP_WIN,
   uint16 TCP_WIN_REV,
   uint64 TCP_OPT,
   uint64 TCP_OPT_REV,
   uint32 TCP_MSS,
   uint32 TCP_MSS_REV,
   uint16 TCP_SYN_SIZE
)

BASICPLUSPlugin::BASICPLUSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

BASICPLUSPlugin::BASICPLUSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(
      plugin_options)
{
   print_stats = module_options.print_stats;
}

FlowCachePlugin *BASICPLUSPlugin::copy()
{
   return new BASICPLUSPlugin(*this);
}

int BASICPLUSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtBASICPLUS *p = new RecordExtBASICPLUS();

   rec.addExtension(p);

   p->ip_ttl[0]  = pkt.ip_ttl;
   p->ip_flg[0]  = pkt.ip_flags;
   p->tcp_mss[0] = pkt.tcp_mss;
   p->tcp_opt[0] = pkt.tcp_options;
   p->tcp_win[0] = pkt.tcp_window;
   if (pkt.tcp_control_bits == 0x02) { // check syn packet
      p->tcp_syn_size = pkt.ip_length;
   }

   return 0;
}

int BASICPLUSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtBASICPLUS *p = (RecordExtBASICPLUS *) rec.getExtension(basicplus);
   uint8_t dir = pkt.source_pkt ? 0 : 1;

   if (p->ip_ttl[dir] < pkt.ip_ttl) {
      p->ip_ttl[dir] = pkt.ip_ttl;
   }
   if (dir && !p->dst_filled) {
      p->ip_ttl[1]  = pkt.ip_ttl;
      p->ip_flg[1]  = pkt.ip_flags;
      p->tcp_mss[1] = pkt.tcp_mss;
      p->tcp_opt[1] = pkt.tcp_options;
      p->tcp_win[1] = pkt.tcp_window;
      p->dst_filled = true;
   }
   return 0;
}

const char *ipfix_basicplus_template[] = {
   IPFIX_BASICPLUS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **BASICPLUSPlugin::get_ipfix_string()
{
   return ipfix_basicplus_template;
}

string BASICPLUSPlugin::get_unirec_field_string()
{
   return BASICPLUS_UNIREC_TEMPLATE;
}

bool BASICPLUSPlugin::include_basic_flow_fields()
{
   return true;
}
