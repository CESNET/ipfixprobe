/**
 * \file phistsplugin.cpp
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

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>

#include "phistsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"
#include "math.h"
#include "ipfix-basiclist.h"

using namespace std;

#define PHISTS_UNIREC_TEMPLATE "S_PHISTS_SIZES,S_PHISTS_IPT,D_PHISTS_SIZES,D_PHISTS_IPT"

#define PHISTS_INCLUDE_ZEROS_OPT "includezeros"

#ifdef DEBUG_PHISTS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif


UR_FIELDS(
   uint32* S_PHISTS_SIZES,
   uint32* S_PHISTS_IPT,
   uint32* D_PHISTS_SIZES,
   uint32* D_PHISTS_IPT
)

const uint32_t PHISTSPlugin::log2_lookup32[32] = { 0,  9,  1,  10, 13, 21, 2,  29,
                                                   11, 14, 16, 18, 22, 25, 3,  30,
                                                   8,  12, 20, 28, 15, 17, 24, 7,
                                                   19, 27, 23, 6,  26, 5,  4,  31 };


PHISTSPlugin::PHISTSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   use_zeros = false;
}

PHISTSPlugin::PHISTSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options)
   : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   use_zeros = false;
   check_plugin_options(plugin_options);
}

FlowCachePlugin *PHISTSPlugin::copy()
{
   return new PHISTSPlugin(*this);
}

/*
 * 0-15     1. bin
 * 16-31    2. bin
 * 32-63    3. bin
 * 64-127   4. bin
 * 128-255  5. bin
 * 256-511  6. bin
 * 512-1023 7. bin
 * 1024 >   8. bin
 */
void PHISTSPlugin::update_hist(RecordExtPHISTS *phists_data, uint32_t value, uint32_t *histogram)
{
   if (value < 16) {
      histogram[0] = no_overflow_increment(histogram[0]);
   } else if (value > 1023) {
      histogram[HISTOGRAM_SIZE - 1] = no_overflow_increment(histogram[HISTOGRAM_SIZE - 1]);
   } else {
      histogram[fastlog2_32(value) - 2 - 1] = no_overflow_increment(histogram[fastlog2_32(value) - 2 -1]);// -2 means shift cause first bin corresponds to 2^4
   }
   return;
}

uint64_t PHISTSPlugin::calculate_ipt(RecordExtPHISTS *phists_data, const struct timeval tv, uint8_t direction)
{
   int64_t ts = IpfixBasicList::Tv2Ts(tv);

   if (phists_data->last_ts[direction] == 0) {
      phists_data->last_ts[direction] = ts;
      return -1;
   }
   int64_t diff = ts - phists_data->last_ts[direction];

   phists_data->last_ts[direction] = ts;
   return diff;
}

void PHISTSPlugin::update_record(RecordExtPHISTS *phists_data, const Packet &pkt)
{
   if(pkt.payload_length_orig == 0 && use_zeros == false){
      return;
   }
   uint8_t direction = (uint8_t) !pkt.source_pkt;
   update_hist(phists_data, (uint32_t) pkt.payload_length_orig, phists_data->size_hist[direction]);
   int32_t ipt_diff = (uint32_t) calculate_ipt(phists_data, pkt.timestamp, direction);
   if (ipt_diff != -1) {
      update_hist(phists_data, (uint32_t) ipt_diff, phists_data->ipt_hist[direction]);
   }
}

int PHISTSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtPHISTS *phists_data = new RecordExtPHISTS();

   rec.addExtension(phists_data);

   update_record(phists_data, pkt);
   return 0;
}

int PHISTSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtPHISTS *phists_data = (RecordExtPHISTS *) rec.getExtension(phists);

   update_record(phists_data, pkt);
   return 0;
}

const char *ipfix_phists_template[] = {
   IPFIX_PHISTS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **PHISTSPlugin::get_ipfix_string()
{
   return ipfix_phists_template;
}

string PHISTSPlugin::get_unirec_field_string()
{
   return PHISTS_UNIREC_TEMPLATE;
}

void PHISTSPlugin::check_plugin_options(vector<plugin_opt>& plugin_options)
{
   stringstream rawoptions(plugin_options[0].params);
   string option;
   vector<string> options;

   while (std::getline(rawoptions, option, ':')) {
      std::transform(option.begin(), option.end(), option.begin(), ::tolower);
      options.push_back(option);
   }

   for (size_t i = 0; i < options.size(); i++) {
      std::cout << options[i] << std::endl;
      if (options[i] == PHISTS_INCLUDE_ZEROS_OPT) {
         DEBUG_MSG("PHISTS include zero-length packets\n");
         use_zeros = true;
      }
   }
}

