/**
 * \file bstats.cpp
 * \brief Plugin for parsing bstats traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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

#include "bstats.hpp"

namespace ipxp {

int RecordExtBSTATS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("bstats", [](){return new BSTATSPlugin();});
   register_plugin(&rec);
   RecordExtBSTATS::REGISTERED_ID = register_extension();
}

const struct timeval BSTATSPlugin::min_packet_in_burst =
{MAXIMAL_INTERPKT_TIME / 1000, (MAXIMAL_INTERPKT_TIME % 1000) * 1000};


BSTATSPlugin::BSTATSPlugin()
{
}

BSTATSPlugin::~BSTATSPlugin()
{
   close();
}

void BSTATSPlugin::init(const char *params)
{
}

void BSTATSPlugin::close()
{
}

ProcessPlugin *BSTATSPlugin::copy()
{
   return new BSTATSPlugin(*this);
}

int BSTATSPlugin::pre_create(Packet &pkt)
{
   return 0;
}

#define BCOUNT burst_count[direction]
void BSTATSPlugin::initialize_new_burst(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt)
{
   bstats_record->brst_pkts[direction][bstats_record->BCOUNT]  = 1;
   bstats_record->brst_bytes[direction][bstats_record->BCOUNT] = pkt.payload_len_wire;
   bstats_record->brst_start[direction][bstats_record->BCOUNT] = pkt.ts;
   bstats_record->brst_end[direction][bstats_record->BCOUNT]   = pkt.ts;
}

bool BSTATSPlugin::belogsToLastRecord(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt)
{
   struct timeval timediff;

   timersub(&pkt.ts, &bstats_record->brst_end[direction][bstats_record->BCOUNT], &timediff);
   if (timercmp(&timediff, &min_packet_in_burst, <)){
      return true;
   }
   return false;
}

bool BSTATSPlugin::isLastRecordBurst(RecordExtBSTATS *bstats_record, uint8_t direction)
{
   if (bstats_record->brst_pkts[direction][bstats_record->BCOUNT] < MINIMAL_PACKETS_IN_BURST){
      return false;
   }
   return true;
}

void BSTATSPlugin::process_bursts(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt)
{
   if (belogsToLastRecord(bstats_record, direction, pkt)){ // does it belong to previous burst?
      bstats_record->brst_pkts[direction][bstats_record->BCOUNT]++;
      bstats_record->brst_bytes[direction][bstats_record->BCOUNT] += pkt.payload_len_wire;
      bstats_record->brst_end[direction][bstats_record->BCOUNT]    = pkt.ts;
      return;
   }
   // the packet does not belong to previous burst
   if (isLastRecordBurst(bstats_record, direction)){
      bstats_record->BCOUNT++;
   }
   if (bstats_record->BCOUNT < BSTATS_MAXELENCOUNT){
      initialize_new_burst(bstats_record, direction, pkt);
   }
}

void BSTATSPlugin::update_record(RecordExtBSTATS *bstats_record, const Packet &pkt)
{
   uint8_t direction = (uint8_t) !pkt.source_pkt;

   if (pkt.payload_len_wire == 0 || bstats_record->BCOUNT >= BSTATS_MAXELENCOUNT){
      // zero-payload or burst array is full
      return;
   }
   if (bstats_record->burst_empty[direction] == 0){
      bstats_record->burst_empty[direction] = 1;
      initialize_new_burst(bstats_record, direction, pkt);
   } else {
      process_bursts(bstats_record, direction, pkt);
   }
}

int BSTATSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtBSTATS *bstats_record = new RecordExtBSTATS();

   rec.add_extension(bstats_record);
   update_record(bstats_record, pkt);
   return 0;
}

int BSTATSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtBSTATS *bstats_record = static_cast<RecordExtBSTATS *>(rec.get_extension(RecordExtBSTATS::REGISTERED_ID));

   update_record(bstats_record, pkt);
   return 0;
}

int BSTATSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void BSTATSPlugin::pre_export(Flow &rec)
{
   uint32_t packets = rec.src_packets + rec.dst_packets;
   if (packets <= MINIMAL_PACKETS_IN_BURST ) {
      rec.remove_extension(RecordExtBSTATS::REGISTERED_ID);
      return;
   }

   RecordExtBSTATS *bstats_record = static_cast<RecordExtBSTATS *>(rec.get_extension(RecordExtBSTATS::REGISTERED_ID));

   for (int direction = 0; direction < 2; direction++){
      if (bstats_record->BCOUNT < BSTATS_MAXELENCOUNT && isLastRecordBurst(bstats_record, direction)){
         bstats_record->BCOUNT++;
      }
   }
}

}
