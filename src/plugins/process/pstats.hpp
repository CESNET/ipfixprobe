/**
 * \file pstats.h
 * \brief Plugin for parsing pstats traffic.
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Karel Hynek <hynekkar@cesnet.cz>
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

#ifndef IPXP_PROCESS_PSTATS_HPP
#define IPXP_PROCESS_PSTATS_HPP

#include <string>
#include <cstring>
#include <sstream>

#ifdef WITH_NEMEA
# include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>

#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#ifndef PSTATS_MAXELEMCOUNT
# define PSTATS_MAXELEMCOUNT 30
#endif

#ifndef PSTATS_MINLEN
# define PSTATS_MINLEN 1
#endif

#define PSTATS_UNIREC_TEMPLATE "PPI_PKT_LENGTHS,PPI_PKT_TIMES,PPI_PKT_FLAGS,PPI_PKT_DIRECTIONS"

UR_FIELDS (
   uint16* PPI_PKT_LENGTHS,
   time* PPI_PKT_TIMES,
   uint8* PPI_PKT_FLAGS,
   int8* PPI_PKT_DIRECTIONS
)

class PSTATSOptParser : public OptionsParser
{
public:
   bool m_include_zeroes;
   bool m_skipdup;

   PSTATSOptParser() : OptionsParser("pstats", "Processing plugin for packet stats"), m_include_zeroes(false), m_skipdup(false)
   {
      register_option("i", "includezeroes", "", "Include zero payload packets", [this](const char *arg){m_include_zeroes = true; return true;}, OptionFlags::NoArgument);
      register_option("s", "skipdup", "", "Skip duplicated TCP packets", [this](const char *arg){m_skipdup = true; return true;}, OptionFlags::NoArgument);
   }
};

/**
 * \brief Flow record extension header for storing parsed PSTATS packets.
 */
struct RecordExtPSTATS : public RecordExt {
   static int REGISTERED_ID;

   uint16_t       pkt_sizes[PSTATS_MAXELEMCOUNT];
   uint8_t        pkt_tcp_flgs[PSTATS_MAXELEMCOUNT];
   struct timeval pkt_timestamps[PSTATS_MAXELEMCOUNT];
   int8_t         pkt_dirs[PSTATS_MAXELEMCOUNT];
   uint16_t       pkt_count;
   uint32_t       tcp_seq[2];
   uint32_t       tcp_ack[2];
   uint16_t       tcp_len[2];
   uint8_t        tcp_flg[2];

   typedef enum eHdrFieldID {
      PktSize  = 1013,
      PktFlags = 1015,
      PktDir   = 1016,
      PktTmstp = 1014
   } eHdrSemantic;

   static const uint32_t CesnetPem = 8057;


   RecordExtPSTATS() : RecordExt(REGISTERED_ID)
   {
      pkt_count = 0;
   }

   #ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_array_allocate(tmplt, record, F_PPI_PKT_TIMES, pkt_count);
      ur_array_allocate(tmplt, record, F_PPI_PKT_LENGTHS, pkt_count);
      ur_array_allocate(tmplt, record, F_PPI_PKT_FLAGS, pkt_count);
      ur_array_allocate(tmplt, record, F_PPI_PKT_DIRECTIONS, pkt_count);

      for (int i = 0; i < pkt_count; i++) {
         ur_time_t ts = ur_time_from_sec_usec(pkt_timestamps[i].tv_sec, pkt_timestamps[i].tv_usec);
         ur_array_set(tmplt, record, F_PPI_PKT_TIMES, i, ts);
         ur_array_set(tmplt, record, F_PPI_PKT_LENGTHS, i, pkt_sizes[i]);
         ur_array_set(tmplt, record, F_PPI_PKT_FLAGS, i, pkt_tcp_flgs[i]);
         ur_array_set(tmplt, record, F_PPI_PKT_DIRECTIONS, i, pkt_dirs[i]);
      }
   }

   const char *get_unirec_tmplt() const
   {
      return PSTATS_UNIREC_TEMPLATE;
   }
   #endif // ifdef WITH_NEMEA

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      int32_t bufferPtr;
      IpfixBasicList basiclist;
      basiclist.hdrEnterpriseNum = IpfixBasicList::CesnetPEM;
      //Check sufficient size of buffer
      int req_size = 4 * basiclist.HeaderSize() /* sizes, times, flags, dirs */ +
                       pkt_count * sizeof(uint16_t) /* sizes */ +
                       2 * pkt_count * sizeof(uint32_t) /* times */ +
                       pkt_count /* flags */ +
                       pkt_count /* dirs */;

      if (req_size > size) {
         return -1;
      }
      // Fill packet sizes
      bufferPtr = basiclist.FillBuffer(buffer, pkt_sizes, pkt_count, (uint16_t) PktSize);
      // Fill timestamps
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, pkt_timestamps, pkt_count,(uint16_t) PktTmstp);
      // Fill tcp flags
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, pkt_tcp_flgs, pkt_count, (uint16_t) PktFlags);
      // Fill directions
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, pkt_dirs, pkt_count,(uint16_t) PktDir);

      return bufferPtr;
   } // fill_ipfix

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_tmplt[] = {
         IPFIX_PSTATS_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_tmplt;
   }
   std::string get_text() const
   {
      std::ostringstream out;
      out << "ppisizes=(";
      for (int i = 0; i < pkt_count; i++) {
         out << pkt_sizes[i];
         if (i != pkt_count - 1) {
            out << ",";
         }
      }
      out << "),ppitimes=(";
      for (int i = 0; i < pkt_count; i++) {
         out << pkt_timestamps[i].tv_sec << "." << pkt_timestamps[i].tv_usec;
         if (i != pkt_count - 1) {
            out << ",";
         }
      }
      out << "),ppiflags=(";
      for (int i = 0; i < pkt_count; i++) {
         out << (uint16_t) pkt_tcp_flgs[i];
         if (i != pkt_count - 1) {
            out << ",";
         }
      }
      out << "),ppidirs=(";
      for (int i = 0; i < pkt_count; i++) {
         out << (int16_t) pkt_dirs[i];
         if (i != pkt_count - 1) {
            out << ",";
         }
      }
      out << ")";
      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing PSTATS packets.
 */
class PSTATSPlugin : public ProcessPlugin
{
public:
   PSTATSPlugin();
   ~PSTATSPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new PSTATSOptParser(); }
   std::string get_name() const { return "pstats"; }
   RecordExt *get_ext() const { return new RecordExtPSTATS(); }
   ProcessPlugin *copy();
   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void update_record(RecordExtPSTATS *pstats_data, const Packet &pkt);
   void pre_export(Flow &rec);

private:
   bool use_zeros;
   bool skip_dup_pkts;
};

}
#endif /* IPXP_PROCESS_PSTATS_HPP */
