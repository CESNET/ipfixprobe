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

#include <iostream>
#include <chrono>

#include "flexprobe-encryption-processing.h"
#include "flexprobe-data.h"
#include "tls.hpp"
#include "http.hpp"
#include "dns.hpp"

//#define TIMEIT

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

        if (encr_data->known_protocol_pattern_id == -1 && data_view->encr_data.pm_flags.items.match_found) {
            encr_data->known_protocol_pattern_id = data_view->encr_data.encr_pattern_id;
            encr_data->known_protocol_position = data_view->encr_data.pattern_offset - pi_pattern_lengths[encr_data->known_protocol_pattern_id]; //- pattern length because PI detects end of the pattern
            encr_data->multiple_pattern_occurence = data_view->encr_data.pm_flags.items.pm_mult_pos;
            encr_data->multiple_patterns = data_view->encr_data.pm_flags.items.pm_mult_pattern;
        }

        return 0;
    }

    void FlexprobeEncryptionProcessing::pre_export(Flow& rec)
    {
        using namespace std::chrono;
        using namespace std::chrono_literals;
        using namespace mlpack;
        auto encr_data = dynamic_cast<FlexprobeEncryptionData*>(rec.get_extension(FlexprobeEncryptionData::REGISTERED_ID));
        if (!encr_data) {
            return;
        }
        // heuristic checking for TLS presence
        auto tls = dynamic_cast<RecordExtTLS*>(rec.get_extension(RecordExtTLS::REGISTERED_ID));
        if (tls != nullptr && tls->version != 0) { // TLS was detected from the start -> automatically assume data was encrypted
            encr_data->classification_result = true;
        } else {
            // compile tracked features into a sample
            arma::vec sample(12);
            sample.at(0) = encr_data->time_interpacket[0].variance();
            sample.at(1) = encr_data->mpe_8bit[0].maximum();
            sample.at(2) = encr_data->mpe_4bit[0].mean();
            sample.at(3) = encr_data->mpe_4bit[0].deviation();
            sample.at(4) = encr_data->mpe_4bit[0].minimum();
            sample.at(5) = encr_data->mpe_4bit[0].maximum();
            sample.at(6) = encr_data->payload_size[0].mean();
            sample.at(7) = encr_data->payload_size[0].variance();
            sample.at(8) = encr_data->payload_size[0].minimum();
            sample.at(9) = encr_data->payload_size[0].maximum();
            sample.at(10) = static_cast<float>(rec.src_packets);
            sample.at(11) = encr_data->mpe_4bit[1].minimum();

#ifdef TIMEIT
            t_start = high_resolution_clock::now();
#endif
            arma::vec proba;
            arma::Row<size_t> result;
            clf_.Classify(sample, result, proba);
#ifndef NDEBUG
            std::cout << std::boolalpha
                      << result.at(0)
                      << " "
                      << bool(result.at(0))
                      << " "
                      << static_cast<unsigned>(proba.at(0) * 100)
                      << " "
                      << static_cast<unsigned>(proba.at(1) * 100)
                      << std::endl;
#endif
            // the ML analysis gives a baseline for evaluation
            ConstrainedValue<unsigned, 0, 100> encr_score(static_cast<unsigned>(proba.at(1) * 100));
#ifndef NDEBUG
            std::cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Base score:" << encr_score << std::endl;
#endif

            // is there a known pattern in data
            if (encr_data->known_protocol_pattern_id != -1) {
#ifndef NDEBUG
                std::cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Known pattern found." << std::endl;
#endif
                encr_score += Scores::KNOWN_PATTERN_FOUND;

                // is the pattern at the beginning?
                if (encr_data->known_protocol_position == 0) {
#ifndef NDEBUG
                    std::cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Pattern is at the beginning." << std::endl;
#endif
                    encr_score += Scores::KNOWN_PATTERN_AT_THE_BEGINNING;
                }

                // does the pattern repeat?
                if (encr_data->multiple_pattern_occurence) {
#ifndef NDEBUG
                    std::cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Pattern repeat." << std::endl;
#endif
                    encr_score -= Scores::REPEATING_PATTERN;
                }

                // are there multiple known patterns?
                if (encr_data->multiple_patterns) {
#ifndef NDEBUG
                    std::cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Multiple known patterns are present." << std::endl;
#endif
                    encr_score -= Scores::MULTIPLE_KNOWN_PATTERNS;
                }
            }

            // is there a known open protocol?
            // requires use of appropriate plugins
            if (rec.get_extension(RecordExtHTTP::REGISTERED_ID) || rec.get_extension(RecordExtDNS::REGISTERED_ID)) {
#ifndef NDEBUG
                std::cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Known open protocol used." << std::endl;
#endif
                encr_score -= Scores::KNOWN_OPEN_PROTOCOL;
            }
#ifdef TIMEIT
            t_end = high_resolution_clock::now();
            std::cout << "Classification: " << duration_cast<nanoseconds>(t_end - t_start).count() << std::endl;
#endif
#ifndef NDEBUG
            std::cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Final score " << encr_score << std::endl;
#endif
            encr_data->classification_result = encr_score > 66;
        }
    }
}
