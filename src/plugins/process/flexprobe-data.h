/**
 * \file flexprobe-data.h
 * \brief Data structures for Flexprobe -- HW accelerated network probe
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

#ifndef IPFIXPROBE_FLEXPROBE_DATA_H
#define IPFIXPROBE_FLEXPROBE_DATA_H

#include <cstdint>
#include <limits>
#include <array>

namespace ipxp
{
    namespace Flexprobe
    {

        using FrameSignature = std::array<unsigned char, 18>;
        using ip_type = std::array<unsigned char, 16>;

        struct Timestamp {
            using seconds_type = std::uint32_t;
            using nanoseconds_type = std::uint32_t;
            using DecimalTimestamp = double;

            seconds_type sec;
            nanoseconds_type nsec;

            DecimalTimestamp to_decimal() const {
                return static_cast<DecimalTimestamp>(sec) + static_cast<DecimalTimestamp>(nsec) * 1e-9f;
            }

            void reset()
            {
                sec = 0;
                nsec = 0;
            }

            void to_max()
            {
                sec = std::numeric_limits<seconds_type>::max();
                nsec = std::numeric_limits<nanoseconds_type>::max();
            }
        };

        struct MpeData
        {
            std::uint16_t expected_count;
            std::uint16_t difference;
        };

        struct [[gnu::packed]] EncryptionData
        {
            std::uint8_t encr_pattern_id;
            union {
                struct {
                    std::uint8_t match_found : 1;
                    std::uint8_t pm_mult_pos : 1;
                    std::uint8_t pm_mult_pattern : 1;
                    std::uint8_t reserved : 5;
                } items;
                std::uint8_t all;
            } pm_flags;
            std::uint16_t pattern_offset;
            MpeData mpe_8bit;
            MpeData mpe_4bit;
        };

        struct DynamicPayloadHeader {
            std::uint16_t dyn_type   :  4;
            std::uint16_t dyn_offset : 12;
            std::uint16_t dyn_length;
        };

        struct [[gnu::packed]] FlexprobeData
        {
            std::uint32_t flow_hash;
            ip_type src_ip;
            ip_type dst_ip;
            std::uint16_t src_port;
            std::uint16_t dst_port;
            std::uint8_t l4_protocol;
            std::uint8_t l4_flags;
            FrameSignature frame_signature;
            std::uint32_t ip_version: 4;
            std::uint32_t interface_in: 4;
            std::uint32_t vlan_0: 12;
            std::uint32_t vlan_1: 12;
            Timestamp arrival_time;
            std::uint16_t packet_size;
            std::uint16_t payload_size;
            std::uint32_t tcp_sequence_no;
            std::uint32_t tcp_acknowledge_no;
            EncryptionData encr_data;
            std::uint16_t dyn_item_count;
            std::uint16_t dyn_payload_length;

            [[nodiscard]]
            size_t static_size() const
            {
                return sizeof(flow_hash)
                       + src_ip.size()
                       + dst_ip.size()
                       + sizeof(src_port)
                       + sizeof(dst_port)
                       + sizeof(l4_protocol)
                       + sizeof(l4_flags)
                       + frame_signature.size()
                       + sizeof(std::uint32_t) // ip_version + interface_in + vlan_0 + vlan_1
                       + sizeof(arrival_time)
                       + sizeof(packet_size)
                       + sizeof(payload_size)
                       + sizeof(tcp_sequence_no)
                       + sizeof(tcp_acknowledge_no)
                       + sizeof(encr_data)
                       + sizeof(dyn_item_count)
                       + sizeof(dyn_payload_length);
            }

            [[nodiscard]]
            size_t size() const
            {
                return static_size() + (dyn_item_count * sizeof(DynamicPayloadHeader));
            }
        };
    }
}

#endif //IPFIXPROBE_FLEXPROBE_DATA_H
