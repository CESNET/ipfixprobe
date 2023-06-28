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
    static PluginRecord rec = PluginRecord("scitags", []() { return new SCITAGSPlugin(); });
    register_plugin(&rec);
    RecordExtSCITAGS::REGISTERED_ID = register_extension();
}

SCITAGSPlugin::SCITAGSPlugin() {}

SCITAGSPlugin::~SCITAGSPlugin() {}

void SCITAGSPlugin::init(const char* params) {}

void SCITAGSPlugin::close() {}

ProcessPlugin* SCITAGSPlugin::copy()
{
    return new SCITAGSPlugin(*this);
}

void SCITAGSPlugin::update_record(RecordExtSCITAGS* record, const Packet& pkt)
{
    if (record->flow_label_set == false) {
        record->flow_label = pkt.ipv6_flowlabel;
        record->flow_label_set = true;
        return;
    }

    if (ntohl(pkt.ipv6_flowlabel) != record->flow_label) {
        // non constant value across the flow, set to 0
        record->non_constant_flow_label = true;
    }

    return;
}

int SCITAGSPlugin::post_create(Flow& rec, const Packet& pkt)
{
    if (pkt.ip_version != 6) {
        return 0;
    }
    RecordExtSCITAGS* data = new RecordExtSCITAGS();
    if (data == nullptr) {
        return 1;
    }
    rec.add_extension(data);

    update_record(data, pkt);
    return 0;
}

int SCITAGSPlugin::post_update(Flow& rec, const Packet& pkt)
{
    if (pkt.ip_version != 6) {
        return 0;
    }
    RecordExtSCITAGS* data = (RecordExtSCITAGS*) rec.get_extension(RecordExtSCITAGS::REGISTERED_ID);

    if (data != nullptr && data->non_constant_flow_label == false) {
        update_record(data, pkt);
    }

    return 0;
}

uint32_t SCITAGSPlugin::bit_reverse(uint32_t value, uint8_t MSB)
{
    uint32_t result = 0;
    for (int i = 0; i < MSB; i++) {
        uint8_t bit = (value & (1 << i)) >> i;
        result |= bit << (MSB - i - 1);
    }
    return result;
}

void SCITAGSPlugin::pre_export(Flow& rec)
{
    RecordExtSCITAGS* record
        = (RecordExtSCITAGS*) rec.get_extension(RecordExtSCITAGS::REGISTERED_ID);
    if (record == nullptr) {
        return;
    }

    if (record->non_constant_flow_label == true) {
        rec.remove_extension(RecordExtSCITAGS::REGISTERED_ID);
        return;
    }
    // Experiment identifier is encoded in 9 bits 14-22 (MSB is bit 0)
    //(bits are in reversed order to allow for possible future adjustments)
    record->experiment_id = bit_reverse((record->flow_label & 0x0003FE00) >> 9, 9);
    // Activity identifier is encoded in 6 bits in position 24-29 (MSB is bit 0)
    record->experiment_activity = (record->flow_label & 0x000000FC) >> 2;
}

} // namespace ipxp
