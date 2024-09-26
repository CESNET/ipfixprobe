/**
 * \file basicplus.hpp
 * \brief Plugin for parsing basicplus traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
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

#ifndef IPXP_PROCESS_BASICPLUS_HPP
#define IPXP_PROCESS_BASICPLUS_HPP

#include <string>
#include <sstream>

#ifdef WITH_NEMEA
 #include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define BASICPLUS_UNIREC_TEMPLATE \
   "IP_TTL,IP_TTL_REV,IP_FLG,IP_FLG_REV,TCP_WIN,TCP_WIN_REV,TCP_OPT,TCP_OPT_REV,TCP_MSS,TCP_MSS_REV,TCP_SYN_SIZE"

UR_FIELDS (
   uint8 IP_TTL,
   uint8 IP_TTL_REV,
   uint8 IP_FLG,
   uint8 IP_FLG_REV,
   uint16 TCP_WIN,
   uint16 TCP_WIN_REV,
   uint64 TCP_OPT,
   uint64 TCP_OPT_REV,
   uint32 TCP_MSS,
   uint32 TCP_MSS_REV,
   uint16 TCP_SYN_SIZE
)

/**
 * \brief Flow record extension header for storing parsed BASICPLUS packets.
 */
struct RecordExtBASICPLUS : public RecordExt {
   static int REGISTERED_ID;

   uint8_t  ip_ttl[2];
   uint8_t  ip_flg[2];
   uint16_t tcp_win[2];
   uint64_t tcp_opt[2];
   uint32_t tcp_mss[2];
   uint16_t tcp_syn_size;

   bool     dst_filled;

   RecordExtBASICPLUS() : RecordExt(REGISTERED_ID)
   {
      ip_ttl[0]    = 0;
      ip_ttl[1]    = 0;
      ip_flg[0]    = 0;
      ip_flg[1]    = 0;
      tcp_win[0]   = 0;
      tcp_win[1]   = 0;
      tcp_opt[0]   = 0;
      tcp_opt[1]   = 0;
      tcp_mss[0]   = 0;
      tcp_mss[1]   = 0;
      tcp_syn_size = 0;

      dst_filled = false;
   }

   #ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_IP_TTL, ip_ttl[0]);
      ur_set(tmplt, record, F_IP_TTL_REV, ip_ttl[1]);
      ur_set(tmplt, record, F_IP_FLG, ip_flg[0]);
      ur_set(tmplt, record, F_IP_FLG_REV, ip_flg[1]);
      ur_set(tmplt, record, F_TCP_WIN, tcp_win[0]);
      ur_set(tmplt, record, F_TCP_WIN_REV, tcp_win[1]);
      ur_set(tmplt, record, F_TCP_OPT, tcp_opt[0]);
      ur_set(tmplt, record, F_TCP_OPT_REV, tcp_opt[1]);
      ur_set(tmplt, record, F_TCP_MSS, tcp_mss[0]);
      ur_set(tmplt, record, F_TCP_MSS_REV, tcp_mss[1]);
      ur_set(tmplt, record, F_TCP_SYN_SIZE, tcp_syn_size);
   }

   const char *get_unirec_tmplt() const
   {
      return BASICPLUS_UNIREC_TEMPLATE;
   }
   #endif // ifdef WITH_NEMEA

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      if (size < 34) {
         return -1;
      }

      buffer[0] = ip_ttl[0];
      buffer[1] = ip_ttl[1];
      buffer[2] = ip_flg[0];
      buffer[3] = ip_flg[1];
      *(uint16_t *) (buffer + 4)  = ntohs(tcp_win[0]);
      *(uint16_t *) (buffer + 6)  = ntohs(tcp_win[1]);
      *(uint64_t *) (buffer + 8)  = swap_uint64(tcp_opt[0]);
      *(uint64_t *) (buffer + 16) = swap_uint64(tcp_opt[1]);
      *(uint32_t *) (buffer + 24) = ntohl(tcp_mss[0]);
      *(uint32_t *) (buffer + 28) = ntohl(tcp_mss[1]);
      *(uint16_t *) (buffer + 32) = ntohs(tcp_syn_size);

      return 34;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_tmplt[] = {
         IPFIX_BASICPLUS_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_tmplt;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "sttl=" << (uint16_t) ip_ttl[0] << ",dttl=" << (uint16_t) ip_ttl[1]
         << ",sflg=" << (uint16_t) ip_flg[0] << ",dflg=" << (uint16_t) ip_flg[1]
         << ",stcpw=" << tcp_win[0] << ",dtcpw=" << tcp_win[1]
         << ",stcpo=" << tcp_opt[0] << ",dtcpo=" << tcp_opt[1]
         << ",stcpm=" << tcp_mss[0] << ",dtcpm=" << tcp_mss[1]
         << ",tcpsynsize=" << tcp_syn_size;
      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing BASICPLUS packets.
 */
class BASICPLUSPlugin : public ProcessPlugin
{
public:
   BASICPLUSPlugin();
   ~BASICPLUSPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("basicplus", "Extend basic fields with TTL, TCP window, options, MSS and SYN size"); }
   std::string get_name() const { return "basicplus"; }
   RecordExt *get_ext() const { return new RecordExtBASICPLUS(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
};

}
#endif /* IPXP_PROCESS_BASICPLUS_HPP */
