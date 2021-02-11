/**
 * \file basicplusplugin.h
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

#ifndef BASICPLUSPLUGIN_H
#define BASICPLUSPLUGIN_H

#include <string>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "byte-utils.h"
#include "ipfixprobe.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed BASICPLUS packets.
 */
struct RecordExtBASICPLUS : RecordExt {
   uint8_t ip_ttl[2];
   uint8_t ip_flg[2];
   uint16_t tcp_win[2];
   uint64_t tcp_opt[2];
   uint32_t tcp_mss[2];

   bool dst_filled;

   RecordExtBASICPLUS() : RecordExt(basicplus)
   {
      ip_ttl[0] = 0;
      ip_ttl[1] = 0;
      ip_flg[0] = 0;
      ip_flg[1] = 0;
      tcp_win[0] = 0;
      tcp_win[1] = 0;
      tcp_opt[0] = 0;
      tcp_opt[1] = 0;
      tcp_mss[0] = 0;
      tcp_mss[1] = 0;

      dst_filled = false;
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_IP_TTL, ip_ttl[0]);
      ur_set(tmplt, record, F_IP_TTL_REV, ip_ttl[1]);
      ur_set(tmplt, record, F_IP_FLG, ip_flg[0]);
      ur_set(tmplt, record, F_IP_FLG_REV, ip_flg[1]);
      ur_set(tmplt, record, F_TCP_WIN, tcp_win[0]);
      ur_set(tmplt, record, F_TCP_WIN_REV, tcp_win[1]);
      ur_set(tmplt, record, F_TCP_OPT, tcp_opt[0]);
      ur_set(tmplt, record, F_TCP_OPT_REV, tcp_opt[1]);
      ur_set(tmplt, record, F_TCP_MSS, tcp_mss[0]);
      ur_set(tmplt, record, F_TCP_MSS_REV, tcp_mss[1]);
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      if (size < 32) {
         return -1;
      }

      buffer[0] = ip_ttl[0];
      buffer[1] = ip_ttl[1];
      buffer[2] = ip_flg[0];
      buffer[3] = ip_flg[1];
      *(uint16_t *) (buffer + 4) = ntohs(tcp_win[0]);
      *(uint16_t *) (buffer + 6) = ntohs(tcp_win[1]);
      *(uint64_t *) (buffer + 8) = swap_uint64(tcp_opt[0]);
      *(uint64_t *) (buffer + 16) = swap_uint64(tcp_opt[1]);
      *(uint32_t *) (buffer + 24) = ntohl(tcp_mss[0]);
      *(uint32_t *) (buffer + 28) = ntohl(tcp_mss[1]);

      return 32;
   }
};

/**
 * \brief Flow cache plugin for parsing BASICPLUS packets.
 */
class BASICPLUSPlugin : public FlowCachePlugin
{
public:
   BASICPLUSPlugin(const options_t &module_options);
   BASICPLUSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif

