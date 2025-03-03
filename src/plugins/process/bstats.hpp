/**
 * \file bstats.hpp
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

#ifndef IPXP_PROCESS_BSTATS_HPP
#define IPXP_PROCESS_BSTATS_HPP

#include <string>
#include <cstring>
#include <sstream>
#include <vector>

#ifdef WITH_NEMEA
# include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define BSTATS_MAXELENCOUNT 15

// BURST CHARACTERISTIC
#define MINIMAL_PACKETS_IN_BURST 3    // in packets
#define MAXIMAL_INTERPKT_TIME    1000 // in miliseconds
                                      // maximal time between consecutive in-burst packets
#define BSTATS_SOURCE            0
#define BSTATS_DEST              1

#define BSTATS_UNIREC_TEMPLATE "SBI_BRST_PACKETS,SBI_BRST_BYTES,SBI_BRST_TIME_START,SBI_BRST_TIME_STOP,\
                                DBI_BRST_PACKETS,DBI_BRST_BYTES,DBI_BRST_TIME_START,DBI_BRST_TIME_STOP"

UR_FIELDS(
   uint32* SBI_BRST_BYTES,
   uint32* SBI_BRST_PACKETS,
   time* SBI_BRST_TIME_START,
   time* SBI_BRST_TIME_STOP,
   uint32* DBI_BRST_PACKETS,
   uint32* DBI_BRST_BYTES,
   time* DBI_BRST_TIME_START,
   time* DBI_BRST_TIME_STOP
)

/**
 * \brief Flow record extension header for storing parsed BSTATS packets.
 */
struct RecordExtBSTATS : public RecordExt {
   typedef enum eHdrFieldID {
      SPkts  = 1050,
      SBytes = 1051,
      SStart = 1052,
      SStop  = 1053,
      DPkts  = 1054,
      DBytes = 1055,
      DStart = 1056,
      DStop  = 1057
   } eHdrFieldID;

   static int REGISTERED_ID;

   uint16_t       burst_count[2];
   uint8_t        burst_empty[2];

   uint32_t       brst_pkts[2][BSTATS_MAXELENCOUNT];
   uint32_t       brst_bytes[2][BSTATS_MAXELENCOUNT];
   struct timeval brst_start[2][BSTATS_MAXELENCOUNT];
   struct timeval brst_end[2][BSTATS_MAXELENCOUNT];

   RecordExtBSTATS() : RecordExt(REGISTERED_ID)
   {
      memset(burst_count, 0, 2 * sizeof(uint16_t));
      memset(burst_empty, 0, 2 * sizeof(uint8_t));
      brst_pkts[BSTATS_DEST][0]   = 0;
      brst_pkts[BSTATS_SOURCE][0] = 0;
   }

   #ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
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

      for (int i = 0; i < burst_count[BSTATS_SOURCE]; i++){
         ts_start = ur_time_from_sec_usec(brst_start[BSTATS_SOURCE][i].tv_sec, brst_start[BSTATS_SOURCE][i].tv_usec);
         ts_stop  = ur_time_from_sec_usec(brst_end[BSTATS_SOURCE][i].tv_sec, brst_end[BSTATS_SOURCE][i].tv_usec);
         ur_array_set(tmplt, record, F_SBI_BRST_PACKETS, i, brst_pkts[BSTATS_SOURCE][i]);
         ur_array_set(tmplt, record, F_SBI_BRST_BYTES, i, brst_bytes[BSTATS_SOURCE][i]);
         ur_array_set(tmplt, record, F_SBI_BRST_TIME_START, i, ts_start);
         ur_array_set(tmplt, record, F_SBI_BRST_TIME_STOP, i, ts_stop);
      }
      for (int i = 0; i < burst_count[BSTATS_DEST]; i++){
         ts_start = ur_time_from_sec_usec(brst_start[BSTATS_DEST][i].tv_sec, brst_start[BSTATS_DEST][i].tv_usec);
         ts_stop  = ur_time_from_sec_usec(brst_end[BSTATS_DEST][i].tv_sec, brst_end[BSTATS_DEST][i].tv_usec);
         ur_array_set(tmplt, record, F_DBI_BRST_PACKETS, i, brst_pkts[BSTATS_DEST][i]);
         ur_array_set(tmplt, record, F_DBI_BRST_BYTES, i, brst_bytes[BSTATS_DEST][i]);
         ur_array_set(tmplt, record, F_DBI_BRST_TIME_START, i, ts_start);
         ur_array_set(tmplt, record, F_DBI_BRST_TIME_STOP, i, ts_stop);
      }
   }

   const char *get_unirec_tmplt() const
   {
      return BSTATS_UNIREC_TEMPLATE;
   }
   #endif // ifdef WITH_NEMEA

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      int32_t bufferPtr;
      IpfixBasicList basiclist;

      basiclist.hdrEnterpriseNum = IpfixBasicList::CesnetPEM;
      // Check sufficient size of buffer
      int req_size = 8 * basiclist.HeaderSize()             /* sizes, times, flags, dirs */
        + 2 * burst_count[BSTATS_SOURCE] * sizeof(uint32_t) /* bytes+sizes */
        + 2 * burst_count[BSTATS_SOURCE] * sizeof(uint64_t) /* times_start + time_end */
        + 2 * burst_count[BSTATS_DEST] * sizeof(uint32_t)   /* bytes+sizes */
        + 2 * burst_count[BSTATS_DEST] * sizeof(uint64_t) /* times_start + time_end */;

      if (req_size > size){
         return -1;
      }
      // Fill buffer
      bufferPtr  = basiclist.FillBuffer(buffer, brst_pkts[BSTATS_SOURCE], burst_count[BSTATS_SOURCE], (uint16_t) SPkts);
      bufferPtr +=
        basiclist.FillBuffer(buffer + bufferPtr, brst_bytes[BSTATS_SOURCE], burst_count[BSTATS_SOURCE],
          (uint16_t) SBytes);
      bufferPtr +=
        basiclist.FillBuffer(buffer + bufferPtr, brst_start[BSTATS_SOURCE], burst_count[BSTATS_SOURCE],
          (uint16_t) SStart);
      bufferPtr +=
        basiclist.FillBuffer(buffer + bufferPtr, brst_end[BSTATS_SOURCE], burst_count[BSTATS_SOURCE], (uint16_t) SStop);

      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_pkts[BSTATS_DEST], burst_count[BSTATS_DEST],
          (uint16_t) DPkts);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_bytes[BSTATS_DEST], burst_count[BSTATS_DEST],
          (uint16_t) DBytes);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_start[BSTATS_DEST], burst_count[BSTATS_DEST],
          (uint16_t) DStart);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, brst_end[BSTATS_DEST], burst_count[BSTATS_DEST],
          (uint16_t) DStop);

      return bufferPtr;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_tmplt[] = {
         IPFIX_BSTATS_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_tmplt;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      char dirs_c[2] = {'s', 'd'};
      int dirs[2] = {BSTATS_SOURCE, BSTATS_DEST};

      for (int j = 0; j < 2; j++) {
         int dir = dirs[j];
         out << dirs_c[j] << "burstpkts=(";
         for (int i = 0; i < burst_count[dir]; i++) {
            out << brst_pkts[dir][i];
            if (i != burst_count[dir] - 1) {
               out << ",";
            }
         }
         out << ")," << dirs_c[j] << "burstbytes=(";
         for (int i = 0; i < burst_count[dir]; i++) {
            out << brst_bytes[dir][i];
            if (i != burst_count[dir] - 1) {
               out << ",";
            }
         }
         out << ")," << dirs_c[j] << "bursttime=(";
         for (int i = 0; i < burst_count[dir]; i++) {
            struct timeval start = brst_start[dir][i];
            struct timeval end = brst_end[dir][i];
            out << start.tv_sec << "." << start.tv_usec << "-" << end.tv_sec << "." << end.tv_usec;
            if (i != burst_count[dir] - 1) {
               out << ",";
            }
         }
         out << "),";
      }

      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing BSTATS packets.
 */
class BSTATSPlugin : public ProcessPlugin
{
public:
   BSTATSPlugin();
   ~BSTATSPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("bstats", "Compute packet bursts stats"); }
   std::string get_name() const { return "bstats"; }
   RecordExt *get_ext() const { return new RecordExtBSTATS(); }
   ProcessPlugin *copy();

   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);

   static const struct timeval min_packet_in_burst;

private:
   void initialize_new_burst(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt);
   void process_bursts(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt);
   void update_record(RecordExtBSTATS *bstats_record, const Packet &pkt);
   bool isLastRecordBurst(RecordExtBSTATS *bstats_record, uint8_t direction);
   bool belogsToLastRecord(RecordExtBSTATS *bstats_record, uint8_t direction, const Packet &pkt);
};

}
#endif /* IPXP_PROCESS_BSTATS_HPP */
