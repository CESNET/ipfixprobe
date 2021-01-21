/**
 * \file bstatsplugin.cpp
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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
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

#include "bstatsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"


using namespace std;

#define BSTATS_UNIREC_TEMPLATE "SBI_BRST_PACKETS,SBI_BRST_BYTES,SBI_BRST_TIME_START,SBI_BRST_TIME_STOP,\
                                DBI_BRST_PACKETS,DBI_BRST_BYTES,DBI_BRST_TIME_START,DBI_BRST_TIME_STOP"

UR_FIELDS (
   uint32* SBI_BRST_PACKETS,
   uint32* SBI_BRST_BYTES,
   time* SBI_BRST_TIME_START,
   time* SBI_BRST_TIME_STOP,
   uint32* DBI_BRST_PACKETS,
   uint32* DBI_BRST_BYTES,
   time* DBI_BRST_TIME_START,
   time* DBI_BRST_TIME_STOP
)
const struct timeval BSTATSPlugin::min_packet_in_burst = {MAXIMAL_INTERPKT_TIME/1000, (MAXIMAL_INTERPKT_TIME%1000)*1000};


BSTATSPlugin::BSTATSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

BSTATSPlugin::BSTATSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

int BSTATSPlugin::pre_create(Packet &pkt)
{
   return 0;
}


#define BCOUNT burst_count[direction]
void BSTATSPlugin::initialize_new_burst(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt)
{
  bstats_record->brst_pkts[direction][bstats_record->BCOUNT] = 1;
  bstats_record->brst_bytes[direction][bstats_record->BCOUNT] = pkt.payload_length_orig;
  bstats_record->brst_start[direction][bstats_record->BCOUNT] = pkt.timestamp;
  bstats_record->brst_end[direction][bstats_record->BCOUNT] = pkt.timestamp;
}

bool BSTATSPlugin::belogsToLastRecord(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt)
{
  struct timeval timediff;
  timersub(&pkt.timestamp, &bstats_record->brst_end[direction][bstats_record->BCOUNT], &timediff);
  if(timercmp(&timediff, &min_packet_in_burst, < )){
    return true;
  }
  return false;
}

bool BSTATSPlugin::isLastRecordBurst(RecordExtBSTATS *bstats_record, uint8_t direction)
{
  if(bstats_record->brst_pkts[direction][bstats_record->BCOUNT] < MINIMAL_PACKETS_IN_BURST){
    return false;
  }
  return true;
}

void BSTATSPlugin::process_bursts(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt)
{
  if(belogsToLastRecord(bstats_record, direction, pkt)) { // does it belong to previous burst?
    bstats_record->brst_pkts[direction][bstats_record->BCOUNT]++;
    bstats_record->brst_bytes[direction][bstats_record->BCOUNT] += pkt.payload_length_orig;
    bstats_record->brst_end[direction][bstats_record->BCOUNT] = pkt.timestamp;
    return;
  }
  //the packet does not belong to previous burst
  if(isLastRecordBurst(bstats_record, direction)){
    bstats_record->BCOUNT++;
  }
  if(bstats_record->BCOUNT < BSTATS_MAXELENCOUNT)
  {
    initialize_new_burst(bstats_record, direction, pkt);
  }
}

void BSTATSPlugin::update_record(RecordExtBSTATS *bstats_record, const Packet &pkt)
{

  uint8_t direction = (uint8_t) !pkt.source_pkt;
  if(pkt.payload_length_orig == 0 || bstats_record->BCOUNT >= BSTATS_MAXELENCOUNT){
    //zero-payload or burst array is full
    return;
  }
  if(bstats_record -> burst_empty[direction] == 0) {
    bstats_record -> burst_empty[direction] = 1;
    initialize_new_burst(bstats_record, direction, pkt);
  }else{
    process_bursts(bstats_record, direction, pkt);
  }

}

int BSTATSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtBSTATS *bstats_record = new RecordExtBSTATS();
   rec.addExtension(bstats_record);
   memset(bstats_record -> burst_count, 0, 2*sizeof(uint16_t));
   memset(bstats_record -> burst_empty, 0, 2*sizeof(uint8_t));
   // need to null first value in brst_pkts
   bstats_record -> brst_pkts[BSTATS_SOURCE][0] = 0;
   bstats_record -> brst_pkts[BSTATS_DEST][0] = 0;
   update_record(bstats_record, pkt);
   return 0;
}

int BSTATSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtBSTATS *bstats_record = static_cast<RecordExtBSTATS *>(rec.getExtension(bstats));
   update_record(bstats_record, pkt);
   return 0;
}

int BSTATSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void BSTATSPlugin::pre_export(Flow &rec)
{
  RecordExtBSTATS *bstats_record = static_cast<RecordExtBSTATS *>(rec.getExtension(bstats));
  for (int direction = 0; direction < 2; direction++){
    if(bstats_record->BCOUNT < BSTATS_MAXELENCOUNT && isLastRecordBurst(bstats_record, direction))
    {
      bstats_record->BCOUNT++;
    }
  }
}

void BSTATSPlugin::finish()
{
   if (print_stats) {
      //cout << "BSTATS plugin stats:" << endl;
   }
}

const char *ipfix_bstats_template[] = {
   IPFIX_BSTATS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **BSTATSPlugin::get_ipfix_string()
{
   return ipfix_bstats_template;
}

string BSTATSPlugin::get_unirec_field_string()
{
   return BSTATS_UNIREC_TEMPLATE;
}

bool BSTATSPlugin::include_basic_flow_fields()
{
   return true;
}
