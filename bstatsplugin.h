/**
 * \file bstatsplugin.h
 * \brief Plugin for parsing bstats traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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

#ifndef BSTATSPLUGIN_H
#define BSTATSPLUGIN_H

#include <string>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

#define BSTATS_MAXELEMCOUNT 15

using namespace std;

/**
 * \brief Flow record extension header for storing parsed BSTATS packets.
 */
struct RecordExtBSTATS : RecordExt {
  uint16_t burst_count;

  uint16_t source_brst_pkts[BSTATS_MAXELEMCOUNT];
  uint16_t source_brst_bytes[BSTATS_MAXELEMCOUNT];
  struct timeval source_start[BSTATS_MAXELEMCOUNT];
  struct timeval source_end[BSTATS_MAXELEMCOUNT];

  uint16_t dest_brst_pkts[BSTATS_MAXELEMCOUNT];
  uint16_t dest_brst_bytes[BSTATS_MAXELEMCOUNT];
  struct timeval dest_start[BSTATS_MAXELEMCOUNT];
  struct timeval dest_end[BSTATS_MAXELEMCOUNT];

  typedef enum eHdrFieldID
  {
     SPkts = 1050,
     SBytes = 1051,
     SStart = 1052,
     SStop = 1053,
     BPkts = 1054,
     BBytes = 1055,
     BStart = 1056,
     BStop = 1057
  } eHdrSemantic;

   RecordExtBSTATS() : RecordExt(bstats)
   {
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      return 0;
   }
};

/**
 * \brief Flow cache plugin for parsing BSTATS packets.
 */
class BSTATSPlugin : public FlowCachePlugin
{
public:
   BSTATSPlugin(const options_t &module_options);
   BSTATSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif
