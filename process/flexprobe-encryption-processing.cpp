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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
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
        auto direction = pkt.source_pkt ? 0 : 1;

        encr_data->time_interpacket[direction].update(arrival - flow_end, total_packets);
        encr_data->payload_size[direction].update(data_view->payload_size, total_packets);

        if (data_view->payload_size >= 256) {
            encr_data->mpe8_valid_count[direction] += 1;
            encr_data->mpe_8bit[direction].update(static_cast<float>(data_view->encr_data.mpe_8bit.difference) / static_cast<float>(data_view->encr_data.mpe_8bit.expected_count),
                                       encr_data->mpe8_valid_count[direction]);
        }

        if (data_view->payload_size >= 16) {
            encr_data->mpe4_valid_count[direction] += 1;
            encr_data->mpe_4bit[direction].update(static_cast<float>(data_view->encr_data.mpe_4bit.difference) / static_cast<float>(data_view->encr_data.mpe_4bit.expected_count),
                                       encr_data->mpe4_valid_count[direction]);
        }

        return 0;
    }

    void FlexprobeEncryptionProcessing::pre_export(Flow& rec)
    {
        // compile tracked features into a sample
        auto encr_data = dynamic_cast<FlexprobeEncryptionData*>(rec.get_extension(FlexprobeEncryptionData::REGISTERED_ID));
        FlexprobeClassificationSample smp(*encr_data);
        smp.packets_fwd = rec.src_packets;

        // heuristic checking for TLS presence
        auto tls = dynamic_cast<RecordExtTLS*>(rec.get_extension(RecordExtTLS::REGISTERED_ID));
        if (tls != nullptr && tls->version != 0) {
            encr_data->classification_result = true;
        } else {
            if (open_zmq_link_()) {
                // classify sample
                link_->send(zmq::buffer(&smp, sizeof(smp)), zmq::send_flags::dontwait);

                zmq::message_t result(1);
                link_->recv(result);

                if (result.size() == 1) {
                    encr_data->classification_result = result.data<bool>();
                }
            }
        }
    }
}
