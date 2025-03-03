/**
 * \file icmp.hpp
 * \brief Plugin for parsing icmp traffic.
 * \author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
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

#ifndef IPXP_PROCESS_ICMP_HPP
#define IPXP_PROCESS_ICMP_HPP

#include <cstring>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include <sstream>

#include <ipfixprobe/utils.hpp>

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define ICMP_UNIREC_TEMPLATE "L4_ICMP_TYPE_CODE"

UR_FIELDS (
   uint16 L4_ICMP_TYPE_CODE
)

/**
 * \brief Flow record extension header for storing parsed ICMP data.
 */
struct RecordExtICMP : public RecordExt {
   static int REGISTERED_ID;

   uint16_t type_code;

   RecordExtICMP() : RecordExt(REGISTERED_ID)
   {
      type_code = 0;
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_L4_ICMP_TYPE_CODE, ntohs(type_code));
   }

   const char *get_unirec_tmplt() const
   {
      return ICMP_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      const int LEN = 2;

      if (size < LEN) {
         return -1;
      }

      *reinterpret_cast<uint16_t *>(buffer) = type_code;

      return LEN;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_ICMP_TEMPLATE(IPFIX_FIELD_NAMES)
         NULL
      };
      return ipfix_template;
   }

   std::string get_text() const
   {
      // type is on the first byte, code is on the second byte
      auto *type_code = reinterpret_cast<const uint8_t *>(&this->type_code);

      std::ostringstream out;
      out << "type=\"" << static_cast<int>(type_code[0]) << '"'
         << ",code=\"" << static_cast<int>(type_code[1]) << '"';

      return out.str();
   }
};

/**
 * \brief Process plugin for parsing ICMP packets.
 */
class ICMPPlugin : public ProcessPlugin
{
public:
   OptionsParser *get_parser() const { return new OptionsParser("icmp", "Parse ICMP traffic"); }
   std::string get_name() const { return "icmp"; }
   RecordExt *get_ext() const { return new RecordExtICMP(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
};

}
#endif /* IPXP_PROCESS_ICMP_HPP */

