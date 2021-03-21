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
   print_stats = module_options.print_stats;
}

WGPlugin::WGPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

int WGPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int WGPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int WGPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int WGPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void WGPlugin::pre_export(Flow &rec)
{
}

void WGPlugin::finish()
{
   if (print_stats) {
      //cout << "WG plugin stats:" << endl;
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

