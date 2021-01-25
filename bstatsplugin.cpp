/**
 * \file bstatsplugin.cpp
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

#include <iostream>

#include "bstatsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define BSTATS_UNIREC_TEMPLATE "SBI_BRST_PACKETS,SBI_BRST_BYTES,SBI_BRST_TIME_START,SBI_BRST_TIME_STOP,\
                                DBI_BRST_PACKETS,DBI_BRST_BYTES,DBI_BRST_TIME_START,DBI_BRST_TIME_STOP"

UR_FIELDS (
   uint16* SBI_BRST_PACKETS,
   uint16* SBI_BRST_BYTES,
   time* SBI_BRST_TIME_START,
   time* SBI_BRST_TIME_STOP,
   uint16* DBI_BRST_PACKETS,
   uint16* DBI_BRST_BYTES,
   time* DBI_BRST_TIME_START,
   time* DBI_BRST_TIME_STOP
)

BSTATSPlugin::BSTATSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

BSTATSPlugin::BSTATSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

int BSTATSPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int BSTATSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int BSTATSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int BSTATSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void BSTATSPlugin::pre_export(Flow &rec)
{
}

void BSTATSPlugin::finish()
{
   if (print_stats) {
      //cout << "BSTATS plugin stats:" << endl;
   }
}

const char *ipfix__template[] = {
   IPFIX_BSTATS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **BSTATSPlugin::get_ipfix_string()
{
   return ipfix__template;
}

string BSTATSPlugin::get_unirec_field_string()
{
   return BSTATS_UNIREC_TEMPLATE;
}

bool BSTATSPlugin::include_basic_flow_fields()
{
   return true;
}
