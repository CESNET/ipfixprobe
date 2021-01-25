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

#include "phistsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define PHISTS_UNIREC_TEMPLATE "PHISTS_SIZES,PHISTS_IPT" /* TODO: unirec template */

UR_FIELDS (
   uint16* PHISTS_SIZES,
   uint16* PHISTS_IPT,
)

PHISTSPlugin::PHISTSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

PHISTSPlugin::PHISTSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

/*void PHISTSPlugin::update_record(RecordExtPHISTS *phists_data, const Packet &pkt)
{
  printf("updating");
}*/

int PHISTSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int PHISTSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int PHISTSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   //RecordExtPHISTS *phists_data = (RecordExtPHISTS *) rec.getExtension(phists);
   //update_record(phists_data, pkt);
   return 0;
}

void PHISTSPlugin::pre_export(Flow &rec)
{
}

void PHISTSPlugin::finish()
{
   if (print_stats) {
      //cout << "PHISTS plugin stats:" << endl;
   }
}

const char *ipfix__template[] = {
   IPFIX_PHISTS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **PHISTSPlugin::get_ipfix_string()
{
   return ipfix__template;
}

string PHISTSPlugin::get_unirec_field_string()
{
   return PHISTS_UNIREC_TEMPLATE;
}

bool PHISTSPlugin::include_basic_flow_fields()
{
   return true;
}
