/**
 * \file netbios.cpp
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
 *
 *
 */

#include <iostream>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "netbios.hpp"

namespace ipxp {

int RecordExtNETBIOS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("netbios", [](){return new NETBIOSPlugin();});
   register_plugin(&rec);
   RecordExtNETBIOS::REGISTERED_ID = register_extension();
}

NETBIOSPlugin::NETBIOSPlugin() : total_netbios_packets(0)
{
}

NETBIOSPlugin::~NETBIOSPlugin()
{
   close();
}

void NETBIOSPlugin::init(const char *params)
{
}

void NETBIOSPlugin::close()
{
}

ProcessPlugin *NETBIOSPlugin::copy()
{
   return new NETBIOSPlugin(*this);
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
        rec.add_extension(ext);
    } else {
        delete ext;
    }

    return 0;
}

bool NETBIOSPlugin::parse_nbns(RecordExtNETBIOS *rec, const Packet &pkt) {
    const char *payload = reinterpret_cast<const char *>(pkt.payload);

    int qry_cnt = get_query_count(payload, pkt.payload_len);
    payload += sizeof(struct dns_hdr);
    if (qry_cnt < 1) {
        return false;
    }

    return store_first_query(payload, rec);
}

int NETBIOSPlugin::get_query_count(const char *payload, uint16_t payload_length) {
    if (payload_length < sizeof(struct dns_hdr)) {
        return -1;
    }

    struct dns_hdr *hdr = (struct dns_hdr *) payload;
    return ntohs(hdr->question_rec_cnt);
}

bool NETBIOSPlugin::store_first_query(const char *payload, RecordExtNETBIOS *rec) {
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

char NETBIOSPlugin::compress_nbns_name_char(const char *uncompressed) {
    return (((uncompressed[0] - 'A') << 4) | (uncompressed[1] - 'A'));
}

uint8_t NETBIOSPlugin::get_nbns_suffix(const char *uncompressed) {
    return compress_nbns_name_char(uncompressed);
}

void NETBIOSPlugin::finish(bool print_stats) {
    if (print_stats) {
        std::cout << "NETBIOS plugin stats:" << std::endl;
        std::cout << "   Parsed NBNS packets in total: " << total_netbios_packets << std::endl;
    }
}

}
