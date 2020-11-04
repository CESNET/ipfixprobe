/**
 * \file bstatsplugin.h
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

#ifndef BSTATSPLUGIN_H
#define BSTATSPLUGIN_H

#include <string>
#include <cstring>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-basiclist.h"

#define BSTATS_MAXELENCOUNT 15

//BURST CHARACTERISTIC
#define MINIMAL_PACKETS_IN_BURST 3 // in packets
#define MAXIMAL_INTERPKT_TIME 1000 // in miliseconds
                                   // maximal time between consecutive in-burst packets
#define BSTATS_SOURCE 0
#define BSTATS_DEST 1

using namespace std;

/**
 * \brief Flow record extension header for storing parsed BSTATS packets.
 */
struct RecordExtBSTATS : RecordExt {
  typedef enum eHdrFieldID
  {
     SPkts = 1050,
     SBytes = 1051,
     SStart = 1052,
     SStop = 1053,
     DPkts = 1054,
     DBytes = 1055,
     DStart = 1056,
     DStop = 1057
  } eHdrFieldID;



  uint16_t burst_count[2];
  uint8_t burst_empty[2];

  uint32_t brst_pkts[2][BSTATS_MAXELENCOUNT];
  uint32_t brst_bytes[2][BSTATS_MAXELENCOUNT];
  struct timeval brst_start[2][BSTATS_MAXELENCOUNT];
  struct timeval brst_end[2][BSTATS_MAXELENCOUNT];

   RecordExtBSTATS() : RecordExt(bstats)
   {
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
     ur_time_t ts_start, ts_stop;
     ur_array_allocate(tmplt, record, F_SBI_BRST_PACKETS, burst_count[BSTATS_SOURCE]);
     ur_array_allocate(tmplt, record, F_SBI_BRST_BYTES, burst_count[BSTATS_SOURCE]);
     ur_array_allocate(tmplt, record, F_SBI_BRST_TIME_START, burst_count[BSTATS_SOURCE]);
     ur_array_allocate(tmplt, record, F_SBI_BRST_TIME_STOP, burst_count[BSTATS_SOURCE]);

     ur_array_allocate(tmplt, record, F_DBI_BRST_PACKETS, burst_count[BSTATS_DEST]);
     ur_array_allocate(tmplt, record, F_DBI_BRST_BYTES, burst_count[BSTATS_DEST]);
     ur_array_allocate(tmplt, record, F_DBI_BRST_TIME_START, burst_count[BSTATS_DEST]);
     ur_array_allocate(tmplt, record, F_DBI_BRST_TIME_STOP, burst_count[BSTATS_DEST]);

     for (int i = 0; i < burst_count[BSTATS_SOURCE]; i++) {
        ts_start = ur_time_from_sec_usec(brst_start[BSTATS_SOURCE][i].tv_sec, brst_start[BSTATS_SOURCE][i].tv_usec);
        ts_stop = ur_time_from_sec_usec(brst_end[BSTATS_SOURCE][i].tv_sec, brst_end[BSTATS_SOURCE][i].tv_usec);
        ur_array_set(tmplt, record, F_SBI_BRST_PACKETS, i, brst_pkts[BSTATS_SOURCE][i]);
        ur_array_set(tmplt, record, F_SBI_BRST_BYTES, i, brst_bytes[BSTATS_SOURCE][i]);
        ur_array_set(tmplt, record, F_SBI_BRST_TIME_START, i, ts_start);
        ur_array_set(tmplt, record, F_SBI_BRST_TIME_STOP, i, ts_stop);
     }
     for (int i = 0; i < burst_count[BSTATS_DEST]; i++) {
        ts_start = ur_time_from_sec_usec(brst_start[BSTATS_DEST][i].tv_sec, brst_start[BSTATS_DEST][i].tv_usec);
        ts_stop = ur_time_from_sec_usec(brst_end[BSTATS_DEST][i].tv_sec, brst_end[BSTATS_DEST][i].tv_usec);
        ur_array_set(tmplt, record, F_DBI_BRST_PACKETS, i, brst_pkts[BSTATS_DEST][i]);
        ur_array_set(tmplt, record, F_DBI_BRST_BYTES, i, brst_bytes[BSTATS_DEST][i]);
        ur_array_set(tmplt, record, F_DBI_BRST_TIME_START, i, ts_start);
        ur_array_set(tmplt, record, F_DBI_BRST_TIME_STOP, i, ts_stop);
     }
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
     int32_t bufferPtr;
     IpfixBasicList basiclist;
     basiclist.hdrEnterpriseNum = IpfixBasicList::CesnetPEM;
     //Check sufficient size of buffer
     int req_size = 8 * basiclist.HeaderSize() /* sizes, times, flags, dirs */ +
                    2 * burst_count[BSTATS_SOURCE] * sizeof(uint32_t) /* bytes+sizes */ +
                    2 * burst_count[BSTATS_SOURCE] * sizeof(uint64_t) /* times_start + time_end */ +
                    2 * burst_count[BSTATS_DEST] * sizeof(uint32_t) /* bytes+sizes */ +
                    2 * burst_count[BSTATS_DEST] * sizeof(uint64_t) /* times_start + time_end */ ;

     if (req_size > size) {
        return -1;
     }
     // Fill buffer
     bufferPtr = basiclist.FillBuffer(buffer, brst_pkts[BSTATS_SOURCE], burst_count[BSTATS_SOURCE], (uint16_t) SPkts);
     bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_bytes[BSTATS_SOURCE], burst_count[BSTATS_SOURCE], (uint16_t) SBytes);
     bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_start[BSTATS_SOURCE], burst_count[BSTATS_SOURCE], (uint16_t) SStart);
     bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_end[BSTATS_SOURCE], burst_count[BSTATS_SOURCE], (uint16_t) SStop);

     bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_pkts[BSTATS_DEST],burst_count[BSTATS_DEST], (uint16_t) DPkts);
     bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_bytes[BSTATS_DEST], burst_count[BSTATS_DEST], (uint16_t) DBytes);
     bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_start[BSTATS_DEST], burst_count[BSTATS_DEST], (uint16_t) DStart);
     bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_end[BSTATS_DEST], burst_count[BSTATS_DEST], (uint16_t) DStop);

     return bufferPtr;
   }
};

/**
 * \brief Flow cache plugin for parsing BSTATS packets.
 */
class BSTATSPlugin : public FlowCachePlugin
{
public:
   BSTATSPlugin(const options_t &module_options);
   BSTATSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

   static const struct timeval min_packet_in_burst;
private:

   void initialize_new_burst(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt);
   void process_bursts(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt);
   void update_record(RecordExtBSTATS *bstats_record, const Packet &pkt);
   bool isLastRecordBurst(RecordExtBSTATS *bstats_record, uint8_t direction);
   bool belogsToLastRecord(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt);
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif
