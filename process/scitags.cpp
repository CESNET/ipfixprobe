/**
 * \file scitags.cpp
 * \brief Plugin for parsing scitags traffic.
 * \author Karel Hynek <karel.hynek@cesnet.cz>
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

#include "scitags.hpp"

namespace ipxp {

int RecordExtSCITAGS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("scitags", [](){return new SCITAGSPlugin();});
   register_plugin(&rec);
   RecordExtSCITAGS::REGISTERED_ID = register_extension();
}

SCITAGSPlugin::SCITAGSPlugin()
{
}

SCITAGSPlugin::~SCITAGSPlugin()
{
}

void SCITAGSPlugin::init(const char *params)
{
}

void SCITAGSPlugin::close()
{
}

ProcessPlugin *SCITAGSPlugin::copy()
{
   return new SCITAGSPlugin(*this);
}

int SCITAGSPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int SCITAGSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int SCITAGSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int SCITAGSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void SCITAGSPlugin::pre_export(Flow &rec)
{
}

}

