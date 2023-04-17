/**
 * \file icmp.cpp
 * \brief Plugin for parsing icmp traffic.
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

#include "icmp.hpp"

namespace ipxp {

int RecordExtICMP::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("icmp", [](){return new ICMPPlugin();});
   register_plugin(&rec);
   RecordExtICMP::REGISTERED_ID = register_extension();
}

ICMPPlugin::ICMPPlugin()
{
}

ICMPPlugin::~ICMPPlugin()
{
}

void ICMPPlugin::init(const char *params)
{
}

void ICMPPlugin::close()
{
}

ProcessPlugin *ICMPPlugin::copy()
{
   return new ICMPPlugin(*this);
}

int ICMPPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int ICMPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int ICMPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int ICMPPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void ICMPPlugin::pre_export(Flow &rec)
{
}

}
