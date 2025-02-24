/**
 * \file flexprobe-tcp-tracking.cpp
 * \brief TCP tracking for Flexprobe -- HW accelerated network probe
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

#include "flexprobe-tcp-tracking.h"
#include "flexprobe-data.h"

namespace ipxp
{
    int TcpTrackingData::REGISTERED_ID = -1;

    __attribute__((constructor)) static void register_this_plugin()
    {
        static PluginRecord rec = PluginRecord("flexprobe-tcp", []()
        { return new FlexprobeTcpTracking(); });
        register_plugin(&rec);
        TcpTrackingData::REGISTERED_ID = register_extension();
    }

    std::uint32_t
    FlexprobeTcpTracking::advance_expected_seq_(std::uint32_t current_seq, std::uint16_t payload_len, bool syn,
                                                bool fin)
    {
        return current_seq + payload_len + (syn ? 1 : 0) + (fin ? 1 : 0);
    }

    FlowState FlexprobeTcpTracking::check_(TcpTrackingData& td, std::uint32_t tcp_seq, unsigned direction)
    {
        FlowState fs = FlowState::OK;

        if (td.expected_seq[direction] > tcp_seq) {
            if (td.tracker_state[direction] != TrackerState::INLINE) {
                fs = FlowState::PACKET_LOSS;
            }
            td.tracker_state[direction] = TrackerState::AHEAD;
        } else if (td.expected_seq[direction] < tcp_seq) {
            if (td.tracker_state[direction] != TrackerState::INLINE) {
                fs = FlowState::PACKET_LOSS;
            }
            td.tracker_state[direction] = TrackerState::BEHIND;
        } else {
            if (td.tracker_state[direction] == TrackerState::BEHIND) {
                fs = FlowState::PACKET_LOSS;
            }

            td.tracker_state[direction] = TrackerState::INLINE;
        }

        return direction == 0 ? fs : FlowState::OK;
    }

    int FlexprobeTcpTracking::post_create(Flow& rec, const Packet& pkt)
    {
        if (!pkt.custom) {
            return 0;
        }

        if (pkt.ip_proto != 0x6) { // track only TCP
            return 0;
        }

        auto data_view = reinterpret_cast<const Flexprobe::FlexprobeData *>(pkt.custom);

        if (!rec.get_extension(TcpTrackingData::REGISTERED_ID)) {
            auto *td = new TcpTrackingData();

            auto direction = pkt.source_pkt ? 0 : 1;

            td->expected_seq[direction] = advance_expected_seq_(pkt.tcp_seq,
                                                                data_view->payload_size,
                                                                pkt.tcp_flags & 0x2,
                                                                pkt.tcp_flags & 0x1);
            direction = direction == 0 ? 1 : 0;
            td->expected_seq[direction] = pkt.tcp_ack; // TODO: add to HW
            rec.add_extension(td);
        }

        return 0;
    }

    int FlexprobeTcpTracking::post_update(Flow& rec, const Packet& pkt)
    {
        if (!pkt.custom) {
            return 0;
        }

        if (pkt.ip_proto != 0x6) { // track only TCP
            return 0;
        }

        auto data_view = reinterpret_cast<const Flexprobe::FlexprobeData *>(pkt.custom);

        auto tcp_data = dynamic_cast<TcpTrackingData *>(rec.get_extension(TcpTrackingData::REGISTERED_ID));
        auto next_tcp = pkt.tcp_seq;
        auto direction = pkt.source_pkt ? 0 : 1;

        //skip check if SYN and ACK present and dst -> src at 0)
        if ((pkt.tcp_flags & 0x12) && tcp_data->expected_seq[direction] == 0) {
            tcp_data->expected_seq[direction] = advance_expected_seq_(next_tcp,
                                                                      data_view->payload_size,
                                                                      pkt.tcp_flags & 0x2,
                                                                      pkt.tcp_flags & 0x1);
            return 0;
        }
        auto check_result = check_(*tcp_data, next_tcp, direction);
        if (check_result == FlowState::PACKET_LOSS) {
            tcp_data->result = TcpResult::INCOMPLETE;
        }

        switch (tcp_data->tracker_state[direction]) {
            case TrackerState::INLINE:
                tcp_data->expected_seq[direction] = advance_expected_seq_(
                        tcp_data->expected_seq[direction],
                        data_view->payload_size,
                        pkt.tcp_flags & 0x2,
                        pkt.tcp_flags & 0x1);
                break;
            case TrackerState::BEHIND:
                tcp_data->expected_seq[direction] = next_tcp;
                break;
            default:
                break;
        }

        return 0;
    }

}
