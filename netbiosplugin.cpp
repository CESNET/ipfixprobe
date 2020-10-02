/**
 * \file netbiosplugin.cpp
 * \brief Plugin for parsing netbios traffic.
 * \author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
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

#include "netbiosplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define NETBIOS_UNIREC_TEMPLATE "NB_NAME,NB_SUFFIX"

UR_FIELDS (
        string NB_NAME
        uint8 NB_SUFFIX
)

NETBIOSPlugin::NETBIOSPlugin(const options_t &module_options) {
    print_stats = module_options.print_stats;
}

NETBIOSPlugin::NETBIOSPlugin(const options_t &module_options, vector <plugin_opt> plugin_options) : FlowCachePlugin(
        plugin_options) {
    print_stats = module_options.print_stats;
}

int NETBIOSPlugin::post_create(Flow &rec, const Packet &pkt) {
    if (pkt.dst_port == 137 || pkt.src_port == 137) {
        return add_netbios_ext(rec, pkt);
    }

    return 0;
}

int NETBIOSPlugin::post_update(Flow &rec, const Packet &pkt) {
    if (pkt.dst_port == 137 || pkt.src_port == 137) {
        return add_netbios_ext(rec, pkt);
    }

    return 0;
}

int NETBIOSPlugin::add_netbios_ext(Flow &rec, const Packet &pkt) {
    RecordExtNETBIOS *ext = new RecordExtNETBIOS();
    rec.addExtension(ext);
    return 0;
}

void NETBIOSPlugin::finish() {
    if (print_stats) {
        //cout << "NETBIOS plugin stats:" << endl;
    }
}

const char *ipfix__template[] = {
        IPFIX_NETBIOS_TEMPLATE(IPFIX_FIELD_NAMES)
        NULL
};

const char **NETBIOSPlugin::get_ipfix_string() {
    return ipfix__template;
}

string NETBIOSPlugin::get_unirec_field_string() {
    return NETBIOS_UNIREC_TEMPLATE;
}

bool NETBIOSPlugin::include_basic_flow_fields() {
    return true;
}

