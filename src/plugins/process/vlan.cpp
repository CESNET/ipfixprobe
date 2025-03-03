/**
 * \file vlan.cpp
 * \brief Plugin for parsing vlan traffic.
 * \author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
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

#include "vlan.hpp"

namespace ipxp {

int RecordExtVLAN::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("vlan", [](){return new VLANPlugin();});
   register_plugin(&rec);
   RecordExtVLAN::REGISTERED_ID = register_extension();
}

ProcessPlugin *VLANPlugin::copy()
{
   return new VLANPlugin(*this);
}

int VLANPlugin::post_create(Flow &rec, const Packet &pkt)
{
   auto ext = new RecordExtVLAN();
   ext->vlan_id = pkt.vlan_id;
   rec.add_extension(ext);
   return 0;
}

}

