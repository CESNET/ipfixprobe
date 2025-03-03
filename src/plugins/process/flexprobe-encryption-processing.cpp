/**
 * \file flexprobe-encryption-processing.cpp
 * \brief Traffic feature processing for encryption analysis for Flexprobe -- HW accelerated network probe
 * \author Roman Vrana <ivrana@fit.vutbr.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#include "flexprobe-encryption-processing.h"
#include "flexprobe-data.h"

namespace ipxp {

int FlexprobeEncryptionData::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("flexprobe-encrypt", [](){return new FlexprobeEncryptionProcessing();});
   register_plugin(&rec);
   FlexprobeEncryptionData::REGISTERED_ID = register_extension();
}

int FlexprobeEncryptionProcessing::post_create(Flow& rec, const Packet& pkt)
{
    if (!rec.get_extension(FlexprobeEncryptionData::REGISTERED_ID)) {
        auto ext = new FlexprobeEncryptionData();
        rec.add_extension(ext);
    }

    return 0;
}

int FlexprobeEncryptionProcessing::post_update(Flow& rec, const Packet& pkt)
{
    if (!pkt.custom) {
        return 0;
    }

    // convert timestamp to decimal
    auto data_view = reinterpret_cast<const Flexprobe::FlexprobeData*>(pkt.custom);

    auto arrival = data_view->arrival_time.to_decimal();
    Flexprobe::Timestamp::DecimalTimestamp flow_end = static_cast<Flexprobe::Timestamp::DecimalTimestamp>(rec.time_last.tv_sec) + static_cast<Flexprobe::Timestamp::DecimalTimestamp>(rec.time_last.tv_usec) * 1e-6f;
    auto encr_data = dynamic_cast<FlexprobeEncryptionData*>(rec.get_extension(FlexprobeEncryptionData::REGISTERED_ID));
    auto total_packets = rec.src_packets + rec.dst_packets;

    encr_data->time_interpacket.update(arrival - flow_end, total_packets);
    encr_data->payload_size.update(data_view->payload_size, total_packets);

    if (data_view->payload_size >= 256) {
        encr_data->mpe8_valid_count += 1;
        //TODO: update value
        encr_data->mpe_8bit.update(1, encr_data->mpe8_valid_count);
    }

    if (data_view->payload_size >= 16) {
        encr_data->mpe4_valid_count += 1;
        //TODO: update value
        encr_data->mpe_4bit.update(1, encr_data->mpe4_valid_count);
    }

    return 0;
}

}
