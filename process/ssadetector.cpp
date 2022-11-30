/**
 * \file ssadetector.cpp
 * \brief Plugin for detecting ssa sequence.
 * \author Jan Jirák jirakja7@fit.cvut.cz
 * \author Karel Hynek hynekkar@cesnet.cz
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

#include "ssadetector.hpp"

namespace ipxp {

int RecordExtSSADetector::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("ssadetector", [](){return new SSADetectorPlugin();});
   register_plugin(&rec);
   RecordExtSSADetector::REGISTERED_ID = register_extension();
}

SSADetectorPlugin::SSADetectorPlugin()
{
}

SSADetectorPlugin::~SSADetectorPlugin()
{
}

void SSADetectorPlugin::init(const char *params)
{
}

void SSADetectorPlugin::close()
{
}

ProcessPlugin *SSADetectorPlugin::copy()
{
   return new SSADetectorPlugin(*this);
}

int SSADetectorPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int SSADetectorPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int SSADetectorPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int SSADetectorPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void SSADetectorPlugin::pre_export(Flow &rec)
{
}

}

