/**
 * \file mpls.cpp
 * \brief Plugin for parsing mpls traffic.
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

#include "mpls.hpp"

namespace ipxp {

int RecordExtMPLS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
    static PluginRecord rec = PluginRecord("mpls", []() { return new MPLSPlugin(); });
    register_plugin(&rec);
    RecordExtMPLS::REGISTERED_ID = register_extension();
}

ProcessPlugin* MPLSPlugin::copy()
{
    return new MPLSPlugin(*this);
}

int MPLSPlugin::post_create(Flow& rec, const Packet& pkt)
{
    if (pkt.mplsTop == 0) {
        return 0;
    }

    auto ext = new RecordExtMPLS();
    ext->mpls = pkt.mplsTop;

    rec.add_extension(ext);
    return 0;
}

} // namespace ipxp
