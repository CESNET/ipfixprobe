/**
 * \file flow_hash.cpp
 * \brief Plugin for parsing flow_hash traffic.
 * \author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
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

#include "flow_hash.hpp"

namespace ipxp {

int RecordExtFLOW_HASH::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
    static PluginRecord rec = PluginRecord("flow_hash", [](){return new FLOW_HASHPlugin();});
    register_plugin(&rec);
    RecordExtFLOW_HASH::REGISTERED_ID = register_extension();
}

FLOW_HASHPlugin::FLOW_HASHPlugin()
{
}

FLOW_HASHPlugin::~FLOW_HASHPlugin()
{
}

void FLOW_HASHPlugin::init(const char *params)
{
}

void FLOW_HASHPlugin::close()
{
}

ProcessPlugin *FLOW_HASHPlugin::copy()
{
    return new FLOW_HASHPlugin(*this);
}

int FLOW_HASHPlugin::post_create(Flow &rec, const Packet &pkt)
{
    auto ext = new RecordExtFLOW_HASH();

    ext->flow_hash = rec.flow_hash;

    rec.add_extension(ext);

    return 0;
}

}

