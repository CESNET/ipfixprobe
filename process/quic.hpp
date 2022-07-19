/**
 * \file quic.hpp
 * \brief Plugin for parsing quic traffic.
 * \author andrej lukacovic lukacan1@fit.cvut.cz
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

#ifndef IPXP_PROCESS_QUIC_HPP
#define IPXP_PROCESS_QUIC_HPP



#ifdef WITH_NEMEA
#include "fields.h"
#endif


#include "quic_parser.hpp"
#include <ipfixprobe/utils.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <sstream>


namespace ipxp {

#define QUIC_UNIREC_TEMPLATE "QUIC_SNI,QUIC_USER_AGENT,QUIC_VERSION"
UR_FIELDS(
   string QUIC_SNI,
   string QUIC_USER_AGENT,
   uint32 QUIC_VERSION
)

/**
 * \brief Flow record extension header for storing parsed QUIC packets.
 */
struct RecordExtQUIC : public RecordExt {
   static int REGISTERED_ID;
   char sni[BUFF_SIZE]  = { 0 };
   char user_agent[BUFF_SIZE]  = { 0 };
   uint32_t quic_version;

   RecordExtQUIC() : RecordExt(REGISTERED_ID)
   {
      sni[0] = 0;
      user_agent[0] = 0;
      quic_version = 0;
   }

   #ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_QUIC_SNI, sni);
      ur_set_string(tmplt, record, F_QUIC_USER_AGENT, user_agent);
      ur_set(tmplt, record, F_QUIC_VERSION, quic_version);
   }

   const char *get_unirec_tmplt() const
   {
      return QUIC_UNIREC_TEMPLATE;
   }
   #endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      uint16_t len_sni = strlen(sni);
      uint16_t len_user_agent = strlen(user_agent);
      uint16_t len_version = sizeof(quic_version);
      int pos = 0;

      if ((len_sni + 3) + (len_user_agent + 3) + len_version > size) {
         return -1;
      }

      pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) sni, len_sni);
      pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) user_agent, len_user_agent);
      *(uint32_t *)(buffer + pos) = htonl(quic_version);
      pos += len_version;
      return pos;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_QUIC_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "quicsni=\"" << sni << "\"" << "quicuseragent=\"" << user_agent << "\"" << "quicversion=\"" << quic_version << "\"";
      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing QUIC packets.
 */
class QUICPlugin : public ProcessPlugin
{
public:
   QUICPlugin();
   ~QUICPlugin();
   void init(const char *params);
   void close();
   RecordExt *get_ext() const { return new RecordExtQUIC(); }
   OptionsParser *get_parser() const { return new OptionsParser("quic", "Parse QUIC traffic"); }
   std::string get_name() const { return "quic"; }
   ProcessPlugin *copy();

   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void add_quic(Flow &rec, const Packet &pkt);
   void finish(bool print_stats);

private:
   bool     process_quic(RecordExtQUIC *, const Packet&);
   int parsed_initial;
   RecordExtQUIC *quic_ptr;
};

}
#endif /* IPXP_PROCESS_QUIC_HPP */
