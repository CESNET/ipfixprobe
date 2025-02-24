/**
 * \file idpcontent.cpp
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
 *
 *
 */

#include <iostream>

#include "idpcontent.hpp"

namespace ipxp {

int RecordExtIDPCONTENT::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("idpcontent", [](){return new IDPCONTENTPlugin();});
   register_plugin(&rec);
   RecordExtIDPCONTENT::REGISTERED_ID = register_extension();
}

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

IDPCONTENTPlugin::IDPCONTENTPlugin()
{
}

IDPCONTENTPlugin::~IDPCONTENTPlugin()
{
   close();
}

void IDPCONTENTPlugin::init(const char *params)
{
}

void IDPCONTENTPlugin::close()
{
}

ProcessPlugin *IDPCONTENTPlugin::copy()
{
   return new IDPCONTENTPlugin(*this);
}

void IDPCONTENTPlugin::update_record(RecordExtIDPCONTENT *idpcontent_data, const Packet &pkt)
{
   // create ptr into buffers from packet directions
   uint8_t paket_direction = (uint8_t) (!pkt.source_pkt);

   // Check zero-packets and be sure, that the exported content is from both directions
   if (idpcontent_data->pkt_export_flg[paket_direction] != 1 && pkt.payload_len > 0) {
      idpcontent_data->idps[paket_direction].size = MIN(IDPCONTENT_SIZE, pkt.payload_len);
      memcpy(idpcontent_data->idps[paket_direction].data, pkt.payload,
        idpcontent_data->idps[paket_direction].size);
      idpcontent_data->pkt_export_flg[paket_direction] = 1;
   }
}

int IDPCONTENTPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtIDPCONTENT *idpcontent_data = new RecordExtIDPCONTENT();
   memset(idpcontent_data->pkt_export_flg, 0, 2 * sizeof(uint8_t));
   rec.add_extension(idpcontent_data);

   update_record(idpcontent_data, pkt);
   return 0;
}

int IDPCONTENTPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtIDPCONTENT *idpcontent_data = static_cast<RecordExtIDPCONTENT *>(rec.get_extension(RecordExtIDPCONTENT::REGISTERED_ID));
   update_record(idpcontent_data, pkt);
   return 0;
}

}
