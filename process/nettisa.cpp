/**
 * \file nettisa.cpp
 * \brief Plugin for creating NetTiSA flow.
 * \author Josef Koumar koumajos@fit.cvut.cz
 * \date 2023
 */

#include "nettisa.hpp"

#include <cmath>
#include <iostream>

namespace ipxp {

int RecordExtNETTISA::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
    static PluginRecord rec = PluginRecord("nettisa", []() { return new NETTISAPlugin(); });
    register_plugin(&rec);
    RecordExtNETTISA::REGISTERED_ID = register_extension();
}

NETTISAPlugin::NETTISAPlugin() {}

NETTISAPlugin::~NETTISAPlugin() {}

void NETTISAPlugin::init(const char* params) {}

void NETTISAPlugin::close() {}

ProcessPlugin* NETTISAPlugin::copy()
{
    return new NETTISAPlugin(*this);
}

void NETTISAPlugin::update_record(
    RecordExtNETTISA* nettisa_data,
    const Packet& pkt,
    const Flow& rec)
{
    float variation_from_mean = pkt.payload_len_wire - nettisa_data->mean;
    uint32_t n = rec.dst_packets + rec.src_packets;
    long diff_time = fmax(pkt.ts.tv_usec - nettisa_data->prev_time, 0);
    nettisa_data->prev_time = pkt.ts.tv_usec;
    // MEAN
    nettisa_data->mean += (variation_from_mean) / n;
    // MIN
    nettisa_data->min = std::min(nettisa_data->min, pkt.payload_len_wire);
    // MAX
    nettisa_data->max = std::max(nettisa_data->max, pkt.payload_len_wire);
    // ROOT MEAN SQUARE
    nettisa_data->root_mean_square += pow(pkt.payload_len_wire, 2);
    // AVERAGE DISPERSION
    nettisa_data->average_dispersion += abs(variation_from_mean);
    // KURTOSIS
    nettisa_data->kurtosis += pow(variation_from_mean, 4);
    // MEAN SCALED TIME
    nettisa_data->mean_scaled_time
        += (pkt.ts.tv_usec - fmin(pkt.ts.tv_usec, rec.time_first.tv_usec) - nettisa_data->mean_scaled_time) / n;
    // MEAN TIME DIFFERENCES
    nettisa_data->mean_difftimes += (diff_time - nettisa_data->mean_difftimes) / n;
    // MIN
    nettisa_data->min_difftimes = fmin(nettisa_data->min_difftimes, diff_time);
    // MAX
    nettisa_data->max_difftimes = fmax(nettisa_data->max_difftimes, diff_time);
    // TIME DISTRIBUTION
    nettisa_data->time_distribution += abs(nettisa_data->mean_difftimes - diff_time);
    // SWITCHING RATIO
    if (nettisa_data->prev_payload != pkt.packet_len_wire) {
        nettisa_data->switching_ratio += 1;
        nettisa_data->prev_payload = pkt.packet_len_wire;
    }
}

int NETTISAPlugin::post_create(Flow& rec, const Packet& pkt)
{
    RecordExtNETTISA* nettisa_data = new RecordExtNETTISA();
    rec.add_extension(nettisa_data);

    nettisa_data->prev_time = pkt.ts.tv_usec;

    update_record(nettisa_data, pkt, rec);
    return 0;
}

int NETTISAPlugin::post_update(Flow& rec, const Packet& pkt)
{
    RecordExtNETTISA* nettisa_data
        = (RecordExtNETTISA*) rec.get_extension(RecordExtNETTISA::REGISTERED_ID);
    update_record(nettisa_data, pkt, rec);
    return 0;
}

void NETTISAPlugin::pre_export(Flow& rec)
{
    RecordExtNETTISA* nettisa_data
        = (RecordExtNETTISA*) rec.get_extension(RecordExtNETTISA::REGISTERED_ID);
    uint32_t n = rec.src_packets + rec.dst_packets;
    nettisa_data->switching_ratio = nettisa_data->switching_ratio / ((n - 1) / 2);
    nettisa_data->stdev = pow(
        (nettisa_data->root_mean_square / n) - pow((rec.src_bytes + rec.dst_bytes) / n, 2),
        0.5);
    nettisa_data->root_mean_square = pow(nettisa_data->root_mean_square / n, 0.5);
    nettisa_data->average_dispersion = nettisa_data->average_dispersion / n;
    nettisa_data->kurtosis = nettisa_data->kurtosis / (n * pow(nettisa_data->stdev, 4));
    nettisa_data->time_distribution = (nettisa_data->time_distribution / (n - 1))
        / (nettisa_data->max_difftimes - nettisa_data->min);
}

} // namespace ipxp
