/**
 * \file pstatsplugin.cpp
 * \brief Plugin for parsing pstats traffic.
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Karel Hynek <hynekkar@cesnet.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

#include "pstatsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

//#define DEBUG_PSTATS

// Print debug message if debugging is allowed.
#ifdef DEBUG_PSTATS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

using namespace std;

#define PSTATS_UNIREC_TEMPLATE "PPI_PKT_LENGTHS,PPI_PKT_TIMES,PPI_PKT_FLAGS,PPI_PKT_DIRECTIONS"

#define INCLUDE_ZEROS_OPT "includezeros"
#define SKIP_DUP_PACKETS "skipdup"


UR_FIELDS (
   uint16* PPI_PKT_LENGTHS,
   time* PPI_PKT_TIMES,
   uint8* PPI_PKT_FLAGS,
   int8* PPI_PKT_DIRECTIONS
)

PSTATSPlugin::PSTATSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   use_zeros = false;
   skip_dup_pkts = false;
}

void PSTATSPlugin::check_plugin_options(vector<plugin_opt>& plugin_options)
{
   stringstream rawoptions(plugin_options[0].params);
   string option;
   vector<string> options;

   while (std::getline(rawoptions, option, ':')) {
      std::transform(option.begin(), option.end(), option.begin(), ::tolower);
      options.push_back(option);
   }

   for (size_t i = 0; i < options.size(); i++) {
      if (options[i] == INCLUDE_ZEROS_OPT) {
         DEBUG_MSG("PSTATS include zero-length packets\n");
         use_zeros = true;
      } else if (options[i] == SKIP_DUP_PACKETS) {
         DEBUG_MSG("PSTATS skip retransmitted packets\n");
         skip_dup_pkts = true;
      }
   }
}

PSTATSPlugin::PSTATSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   use_zeros = false;
   skip_dup_pkts = false;
   check_plugin_options(plugin_options);
}

FlowCachePlugin *PSTATSPlugin::copy()
{
   return new PSTATSPlugin(*this);
}

inline bool seq_overflowed(uint32_t curr, uint32_t prev)
{
   return (int64_t) curr - (int64_t) prev < -4252017623LL;
}

void PSTATSPlugin::update_record(RecordExtPSTATS *pstats_data, const Packet &pkt)
{
   /**
    * 0 - client -> server
    * 1 - server -> client
    */
   int8_t dir = pkt.source_pkt ? 0 : 1;
   if (skip_dup_pkts && pkt.ip_proto == 6) {
      // Current seq <= previous ack?
      bool seq_susp = (pkt.tcp_seq <= pstats_data->tcp_seq[dir] && !seq_overflowed(pkt.tcp_seq, pstats_data->tcp_seq[dir])) ||
                      (pkt.tcp_seq > pstats_data->tcp_seq[dir] && seq_overflowed(pkt.tcp_seq, pstats_data->tcp_seq[dir]));
      // Current ack <= previous ack?
      bool ack_susp = (pkt.tcp_ack <= pstats_data->tcp_ack[dir] && !seq_overflowed(pkt.tcp_ack, pstats_data->tcp_ack[dir])) ||
                      (pkt.tcp_ack > pstats_data->tcp_ack[dir] && seq_overflowed(pkt.tcp_ack, pstats_data->tcp_ack[dir]));
      if (seq_susp && ack_susp &&
            pkt.payload_length == pstats_data->tcp_len[dir] &&
            pkt.tcp_control_bits == pstats_data->tcp_flg[dir] &&
            pstats_data->pkt_count != 0) {
         return;
      }
   }
   pstats_data->tcp_seq[dir] = pkt.tcp_seq;
   pstats_data->tcp_ack[dir] = pkt.tcp_ack;
   pstats_data->tcp_len[dir] = pkt.payload_length;
   pstats_data->tcp_flg[dir] = pkt.tcp_control_bits;

   if (pkt.payload_length == 0 && use_zeros == false) {
      return;
   }

   /*
    * dir =  1 iff client -> server
    * dir = -1 iff server -> client
    */
   dir = pkt.source_pkt ? 1 : -1;
   if (pstats_data->pkt_count < PSTATS_MAXELEMCOUNT) {
      uint16_t pkt_cnt = pstats_data->pkt_count;
      pstats_data->pkt_sizes[pkt_cnt] = pkt.payload_length_orig;
      pstats_data->pkt_tcp_flgs[pkt_cnt] = pkt.tcp_control_bits;

      pstats_data->pkt_timestamps[pkt_cnt] = pkt.timestamp;

      DEBUG_MSG("PSTATS processed packet %d: Size: %d Timestamp: %ld.%ld\n", pkt_cnt,
            pstats_data->pkt_sizes[pkt_cnt],
            pstats_data->pkt_timestamps[pkt_cnt].tv_sec,
            pstats_data->pkt_timestamps[pkt_cnt].tv_usec);

      pstats_data->pkt_dirs[pkt_cnt] = dir;
      pstats_data->pkt_count++;
   } else {
      /* Do not count more than PSTATS_MAXELEMCOUNT packets */
   }
}

int PSTATSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtPSTATS *pstats_data = new RecordExtPSTATS();
   rec.addExtension(pstats_data);

   update_record(pstats_data, pkt);
   return 0;
}

int PSTATSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtPSTATS *pstats_data = (RecordExtPSTATS *) rec.getExtension(pstats);
   update_record(pstats_data, pkt);
   return 0;
}

const char *ipfix_pstats_template[] = {
   IPFIX_PSTATS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **PSTATSPlugin::get_ipfix_string()
{
   return ipfix_pstats_template;
}

string PSTATSPlugin::get_unirec_field_string()
{
   return PSTATS_UNIREC_TEMPLATE;
}

