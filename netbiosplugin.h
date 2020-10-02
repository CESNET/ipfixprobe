/**
 * \file netbiosplugin.h
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

#ifndef NETBIOSPLUGIN_H
#define NETBIOSPLUGIN_H

#include <string>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "dns.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed NETBIOS packets.
 */
struct RecordExtNETBIOS : RecordExt {
    string netbios_name;
    char netbios_suffix;

    RecordExtNETBIOS() : RecordExt(netbios) {
    }

#ifdef WITH_NEMEA
    virtual void fillUnirec(ur_template_t *tmplt, void *record)
    {
        ur_set_var(tmplt, record, F_NB_SUFFIX, &netbios_suffix, 1);
        ur_set_string(tmplt, record, F_NB_NAME, netbios_name.c_str());
    }
#endif

    virtual int fillIPFIX(uint8_t *buffer, int size) {
        int length = netbios_name.length();

        if (2 + length > size) {
            return -1;
        }

        buffer[0] = netbios_suffix;
        buffer[1] = length;
        memcpy(buffer + 2, netbios_name.c_str(), length);

        return length + 2;
    }
};

/**
 * \brief Flow cache plugin for parsing NETBIOS packets.
 */
class NETBIOSPlugin : public FlowCachePlugin {
public:
    NETBIOSPlugin(const options_t &module_options);

    NETBIOSPlugin(const options_t &module_options, vector <plugin_opt> plugin_options);

    int post_create(Flow &rec, const Packet &pkt);

    int post_update(Flow &rec, const Packet &pkt);

    void finish();

    const char **get_ipfix_string();

    string get_unirec_field_string();

    bool include_basic_flow_fields();

private:
    int add_netbios_ext(Flow &rec, const Packet &pkt);

    bool parse_nbns(RecordExtNETBIOS *rec, const Packet &pkt);

    int get_query_count(char *payload, uint16_t payload_length);

    void store_first_query(char *payload, RecordExtNETBIOS *rec);

    char compress_nbns_name_char(char *uncompressed);

    uint8_t get_nbns_suffix(char *uncompressed);

    bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif

