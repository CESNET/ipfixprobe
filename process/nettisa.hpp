/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, CESNET z.s.p.o.
 */

/**
 * \file nettisa.hpp
 * \brief Class for creating NetTiSA flow.
 * \author Josef Koumar koumajos@fit.cvut.cz
 * \date 2023
 */

#pragma once

#include <limits>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace ipxp {

#define NETTISA_UNIREC_TEMPLATE                                                                    \
    "NTS_MEAN,NTS_MIN,NTS_MAX,NTS_STDEV,NTS_KURTOSIS,NTS_ROOT_MEAN_SQUARE,NTS_"                    \
    "AVERAGE_DISPERSION,"                                                                          \
    "NTS_MEAN_SCALED_TIME,NTS_MEAN_DIFFTIMES,NTS_MIN_DIFFTIMES,NTS_MAX_"                           \
    "DIFFTIMES,NTS_TIME_"                                                                          \
    "DISTRIBUTION,"                                                                                \
    "NTS_SWITCHING_RATIO"

UR_FIELDS(
    float NTS_MEAN,
    uint16 NTS_MIN,
    uint16 NTS_MAX,
    float NTS_STDEV,
    float NTS_KURTOSIS,
    float NTS_ROOT_MEAN_SQUARE,
    float NTS_AVERAGE_DISPERSION,
    float NTS_MEAN_SCALED_TIME,
    float NTS_MEAN_DIFFTIMES,
    float NTS_MIN_DIFFTIMES,
    float NTS_MAX_DIFFTIMES,
    float NTS_TIME_DISTRIBUTION,
    float NTS_SWITCHING_RATIO, )

/**
 * \brief Flow record extension header for storing parsed NETTISA data.
 */
struct RecordExtNETTISA : public RecordExt {
    static int REGISTERED_ID;

    float mean;
    uint16_t min;
    uint16_t max;
    float stdev;
    float kurtosis;
    float root_mean_square;
    float average_dispersion;
    float mean_scaled_time;
    float mean_difftimes;
    float min_difftimes;
    float max_difftimes;
    float time_distribution;
    float switching_ratio;

    uint16_t prev_payload;
    uint64_t prev_time;
    uint64_t sum_payload;

    RecordExtNETTISA()
        : RecordExt(REGISTERED_ID)
    {
        mean = 0;
        min = std::numeric_limits<uint16_t>::max();
        max = 0;
        stdev = 0;
        kurtosis = 0;
        root_mean_square = 0;
        average_dispersion = 0;
        mean_scaled_time = 0;
        mean_difftimes = 0;
        min_difftimes = std::numeric_limits<float>::max();
        max_difftimes = 0;
        time_distribution = 0;
        switching_ratio = 0;

        prev_payload = 0;
        prev_time = 0;
        sum_payload = 0;
    }

#ifdef WITH_NEMEA
    virtual void fill_unirec(ur_template_t* tmplt, void* record)
    {
        ur_set(tmplt, record, F_NTS_MEAN, mean);
        ur_set(tmplt, record, F_NTS_MIN, min);
        ur_set(tmplt, record, F_NTS_MAX, max);
        ur_set(tmplt, record, F_NTS_STDEV, stdev);
        ur_set(tmplt, record, F_NTS_KURTOSIS, kurtosis);
        ur_set(tmplt, record, F_NTS_ROOT_MEAN_SQUARE, root_mean_square);
        ur_set(tmplt, record, F_NTS_AVERAGE_DISPERSION, average_dispersion);
        ur_set(tmplt, record, F_NTS_MEAN_SCALED_TIME, mean_scaled_time);
        ur_set(tmplt, record, F_NTS_MEAN_DIFFTIMES, mean_difftimes);
        ur_set(tmplt, record, F_NTS_MIN_DIFFTIMES, min_difftimes);
        ur_set(tmplt, record, F_NTS_MAX_DIFFTIMES, max_difftimes);
        ur_set(tmplt, record, F_NTS_TIME_DISTRIBUTION, time_distribution);
        ur_set(tmplt, record, F_NTS_SWITCHING_RATIO, switching_ratio);
    }

    const char* get_unirec_tmplt() const { return NETTISA_UNIREC_TEMPLATE; }
#endif // ifdef WITH_NEMEA

    int get_ipfix_size() const noexcept
    {
        return sizeof(mean) + sizeof(min) + sizeof(max) + sizeof(stdev) + sizeof(kurtosis)
            + sizeof(root_mean_square) + sizeof(average_dispersion) + sizeof(mean_scaled_time)
            + sizeof(mean_difftimes) + sizeof(min_difftimes) + sizeof(max_difftimes)
            + sizeof(time_distribution) + sizeof(switching_ratio);
    }

    virtual int fill_ipfix(uint8_t* buffer, int available_ipfix_size)
    {
        int required_ipfix_size = get_ipfix_size();
        if (required_ipfix_size > available_ipfix_size) {
            return -1;
        }

        int pos = 0;
        *(uint32_t*) (buffer + pos) = htonf(mean);
        pos += sizeof(mean);
        *(uint16_t*) (buffer + pos) = htons(min);
        pos += sizeof(min);
        *(uint16_t*) (buffer + pos) = htons(max);
        pos += sizeof(max);
        *(uint32_t*) (buffer + pos) = htonf(stdev);
        pos += sizeof(stdev);
        *(uint32_t*) (buffer + pos) = htonf(kurtosis);
        pos += sizeof(kurtosis);
        *(uint32_t*) (buffer + pos) = htonf(root_mean_square);
        pos += sizeof(root_mean_square);
        *(uint32_t*) (buffer + pos) = htonf(average_dispersion);
        pos += sizeof(average_dispersion);
        *(uint32_t*) (buffer + pos) = htonf(mean_scaled_time);
        pos += sizeof(mean_scaled_time);
        *(uint32_t*) (buffer + pos) = htonf(mean_difftimes);
        pos += sizeof(mean_difftimes);
        *(uint32_t*) (buffer + pos) = htonf(min_difftimes);
        pos += sizeof(min_difftimes);
        *(uint32_t*) (buffer + pos) = htonf(max_difftimes);
        pos += sizeof(max_difftimes);
        *(uint32_t*) (buffer + pos) = htonf(time_distribution);
        pos += sizeof(time_distribution);
        *(uint32_t*) (buffer + pos) = htonf(switching_ratio);
        pos += sizeof(switching_ratio);
        return pos;
    }

    const char** get_ipfix_tmplt() const
    {
        static const char* ipfix_template[] = {IPFIX_NETTISA_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
        return ipfix_template;
    }
};

/**
 * \brief Process plugin for parsing packets for the NetTiSA flow.
 */
class NETTISAPlugin : public ProcessPlugin {
public:
    OptionsParser* get_parser() const { return new OptionsParser("nettisa", "Parse NetTiSA flow"); }
    std::string get_name() const { return "nettisa"; }
    RecordExt* get_ext() const { return new RecordExtNETTISA(); }
    ProcessPlugin* copy();

    int post_create(Flow& rec, const Packet& pkt);
    int post_update(Flow& rec, const Packet& pkt);
    void update_record(RecordExtNETTISA* nettisa_data, const Packet& pkt, const Flow& rec);
    void pre_export(Flow& rec);
};

} // namespace ipxp
