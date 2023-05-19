/**
 * \file phists.cpp
 * \brief Plugin for parsing phists traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>
#include <math.h>

#include "phists.hpp"

namespace ipxp {

int RecordExtPHISTS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("phists", [](){return new PHISTSPlugin();});
   register_plugin(&rec);
   RecordExtPHISTS::REGISTERED_ID = register_extension();
}

#define PHISTS_INCLUDE_ZEROS_OPT "includezeros"

#ifdef DEBUG_PHISTS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

const uint32_t PHISTSPlugin::log2_lookup32[32] = { 0,  9,  1,  10, 13, 21, 2,  29,
                                                   11, 14, 16, 18, 22, 25, 3,  30,
                                                   8,  12, 20, 28, 15, 17, 24, 7,
                                                   19, 27, 23, 6,  26, 5,  4,  31 };

PHISTSPlugin::PHISTSPlugin() : use_zeros(false)
{
}

PHISTSPlugin::~PHISTSPlugin()
{
   close();
}

void PHISTSPlugin::init(const char *params)
{
   PHISTSOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   use_zeros = parser.m_include_zeroes;
}

void PHISTSPlugin::close()
{
}

ProcessPlugin *PHISTSPlugin::copy()
{
   return new PHISTSPlugin(*this);
}

/*
 * 0-15     1. bin
 * 16-31    2. bin
 * 32-63    3. bin
 * 64-127   4. bin
 * 128-255  5. bin
 * 256-511  6. bin
 * 512-1023 7. bin
 * 1024 >   8. bin
 */
void PHISTSPlugin::update_hist(RecordExtPHISTS *phists_data, uint32_t value, uint32_t *histogram)
{
   if (value < 16) {
      histogram[0] = no_overflow_increment(histogram[0]);
   } else if (value > 1023) {
      histogram[HISTOGRAM_SIZE - 1] = no_overflow_increment(histogram[HISTOGRAM_SIZE - 1]);
   } else {
      histogram[fastlog2_32(value) - 2 - 1] = no_overflow_increment(histogram[fastlog2_32(value) - 2 -1]);// -2 means shift cause first bin corresponds to 2^4
   }
   return;
}

uint64_t PHISTSPlugin::calculate_ipt(RecordExtPHISTS *phists_data, const struct timeval tv, uint8_t direction)
{
   int64_t ts = IpfixBasicList::Tv2Ts(tv);

   if (phists_data->last_ts[direction] == 0) {
      phists_data->last_ts[direction] = ts;
      return -1;
   }
   int64_t diff = ts - phists_data->last_ts[direction];

   phists_data->last_ts[direction] = ts;
   return diff;
}

void PHISTSPlugin::update_record(RecordExtPHISTS *phists_data, const Packet &pkt)
{
   if (pkt.payload_len_wire == 0 && use_zeros == false){
      return;
   }
   uint8_t direction = (uint8_t) !pkt.source_pkt;
   update_hist(phists_data, (uint32_t) pkt.payload_len_wire, phists_data->size_hist[direction]);
   int32_t ipt_diff = (uint32_t) calculate_ipt(phists_data, pkt.ts, direction);
   if (ipt_diff != -1) {
      update_hist(phists_data, (uint32_t) ipt_diff, phists_data->ipt_hist[direction]);
   }
}



void PHISTSPlugin::pre_export(Flow &rec)
{
   //do not export phists for single packets flows, usually port scans
   uint32_t packets = rec.src_packets + rec.dst_packets;
   uint8_t flags = rec.src_tcp_flags | rec.dst_tcp_flags;

   if (packets <= PHISTS_MINLEN && (flags & 0x02)) { //tcp SYN set
      rec.remove_extension(RecordExtPHISTS::REGISTERED_ID);
   }
}

int PHISTSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtPHISTS *phists_data = new RecordExtPHISTS();

   rec.add_extension(phists_data);

   update_record(phists_data, pkt);
   return 0;
}

int PHISTSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtPHISTS *phists_data = (RecordExtPHISTS *) rec.get_extension(RecordExtPHISTS::REGISTERED_ID);

   update_record(phists_data, pkt);
   return 0;
}

}
