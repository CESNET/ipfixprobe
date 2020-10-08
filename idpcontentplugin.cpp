/**
 * \file idpcontentplugin.cpp
 * \brief Plugin for parsing idpcontent traffic.
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
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

#include "idpcontentplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define IDPCONTENT_UNIREC_TEMPLATE "IDP_CONTENT,IDP_CONTENT_REV"

UR_FIELDS (
   bytes IDP_CONTENT,
   bytes IDP_CONTENT_REV
)

IDPCONTENTPlugin::IDPCONTENTPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

IDPCONTENTPlugin::IDPCONTENTPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

int IDPCONTENTPlugin::pre_create(Packet &pkt)
{
   return 0;
}

void IDPCONTENTPlugin::update_record(RecordExtIDPCONTENT *idpcontent_data, const Packet &pkt)
{
  //Check zero-packets and be sure, that the exported content is from both directions
  if(idpcontent_data -> fill_counter < EXPORTED_PACKETS && pkt.payload_length > 0 && (uint8_t)(!pkt.source_pkt) == (idpcontent_data -> fill_counter % 2)) {
    idpcontent_data -> idps[idpcontent_data -> fill_counter].size = (pkt.payload_length > IDPCONTENT_SIZE)?IDPCONTENT_SIZE:pkt.payload_length;
    memcpy(idpcontent_data->idps[idpcontent_data -> fill_counter].data, pkt.payload, idpcontent_data -> idps[idpcontent_data -> fill_counter].size);
    idpcontent_data -> fill_counter++;
  }

}

int IDPCONTENTPlugin::post_create(Flow &rec, const Packet &pkt)
{
  RecordExtIDPCONTENT *idpcontent_data = new RecordExtIDPCONTENT();
  idpcontent_data -> fill_counter = 0;
  rec.addExtension(idpcontent_data);

  update_record(idpcontent_data, pkt);
  return 0;
}

int IDPCONTENTPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtIDPCONTENT *idpcontent_data = (RecordExtIDPCONTENT *) rec.getExtension(idpcontent);
   update_record(idpcontent_data, pkt);
   return 0;
}


const char *ipfix__template[] = {
   IPFIX_IDPCONTENT_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **IDPCONTENTPlugin::get_ipfix_string()
{
   return ipfix__template;
}

string IDPCONTENTPlugin::get_unirec_field_string()
{
   return IDPCONTENT_UNIREC_TEMPLATE;
}
