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

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "netbiosplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define NETBIOS_UNIREC_TEMPLATE "NB_NAME,NB_SUFFIX"

UR_FIELDS (
    string NB_NAME,
    uint8 NB_SUFFIX
)

NETBIOSPlugin::NETBIOSPlugin(const options_t &module_options) {
    print_stats = module_options.print_stats;
    total_netbios_packets = 0;
}

NETBIOSPlugin::NETBIOSPlugin(const options_t &module_options, vector <plugin_opt> plugin_options) : FlowCachePlugin(
        plugin_options) {
    print_stats = module_options.print_stats;
    total_netbios_packets = 0;
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
    if (parse_nbns(ext, pkt)) {
        total_netbios_packets++;
        rec.addExtension(ext);
    } else {
        delete ext;
    }

    return 0;
}

bool NETBIOSPlugin::parse_nbns(RecordExtNETBIOS *rec, const Packet &pkt) {
    char *payload = pkt.payload;

    int qry_cnt = get_query_count(payload, pkt.payload_length);
    payload += sizeof(struct dns_hdr);
    if (qry_cnt < 1) {
        return false;
    }

    return store_first_query(payload, rec);
}

int NETBIOSPlugin::get_query_count(char *payload, uint16_t payload_length) {
    if (payload_length < sizeof(struct dns_hdr)) {
        return -1;
    }

    struct dns_hdr *hdr = (struct dns_hdr *) payload;
    return ntohs(hdr->question_rec_cnt);
}

bool NETBIOSPlugin::store_first_query(char *payload, RecordExtNETBIOS *rec) {
    uint8_t nb_name_length = *payload++;
    if (nb_name_length != 32) {
        return false;
    }

    rec->netbios_name = "";
    for (int i = 0; i < nb_name_length; i += 2, payload += 2) {
        if (i != 30) {
            rec->netbios_name += compress_nbns_name_char(payload);
        } else {
            rec->netbios_suffix = get_nbns_suffix(payload);
        }
    }
    return true;
}

char NETBIOSPlugin::compress_nbns_name_char(char *uncompressed) {
    return (((uncompressed[0] - 'A') << 4) | (uncompressed[1] - 'A'));
}

uint8_t NETBIOSPlugin::get_nbns_suffix(char *uncompressed) {
    return compress_nbns_name_char(uncompressed);
}

void NETBIOSPlugin::finish() {
    if (print_stats) {
        cout << "NETBIOS plugin stats:" << endl;
        cout << "   Parsed NBNS packets in total: " << total_netbios_packets << endl;
    }
}

const char *ipfix_netbios_template[] = {
        IPFIX_NETBIOS_TEMPLATE(IPFIX_FIELD_NAMES)
        NULL
};

const char **NETBIOSPlugin::get_ipfix_string() {
    return ipfix_netbios_template;
}

string NETBIOSPlugin::get_unirec_field_string() {
    return NETBIOS_UNIREC_TEMPLATE;
}

bool NETBIOSPlugin::include_basic_flow_fields() {
    return true;
}

