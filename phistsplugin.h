/**
 * \file phistsplugin.h
 * \brief Plugin for parsing phists traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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

#ifndef PHISTSPLUGIN_H
#define PHISTSPLUGIN_H

#include <string>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

using namespace std;

#define HISTOGRAM_SIZE 8

/**
 * \brief Flow record extension header for storing parsed PHISTS packets.
 */
struct RecordExtPHISTS : RecordExt {

   uint16_t size_hist[HISTOGRAM_SIZE];
   uint16_t ipt_hist[HISTOGRAM_SIZE];

   RecordExtPHISTS() : RecordExt(phists)
   {
     //inicializing histograms with zeros
     memset(size_hist, 0, sizeof(uint16_t) * HISTOGRAM_SIZE);
     memset(ipt_hist, 0, sizeof(uint16_t) * HISTOGRAM_SIZE);
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_array_allocate(tmplt, record, F_PHISTS_SIZES, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_PHISTS_IPT, HISTOGRAM_SIZE);

      for (int i = 0; i < HISTOGRAM_SIZE; i++) {
         ur_array_set(tmplt, record, F_PHISTS_SIZES, i, size_hist[i]);
         ur_array_set(tmplt, record, F_PHISTS_IPT, i, ipt_hist[i]);
      }
   }
#endif // ifdef WITH_NEMEA

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      return 0;
   }
};

/**
 * \brief Flow cache plugin for parsing PHISTS packets.
 */
class PHISTSPlugin : public FlowCachePlugin
{
public:
   PHISTSPlugin(const options_t &module_options);
   PHISTSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
   //void update_record(RecordExtPHISTS *phists_data, const Packet &pkt);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif
