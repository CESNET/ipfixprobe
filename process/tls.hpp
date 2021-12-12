/**
 * \file tls.hpp
 * \brief Plugin for parsing https traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
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

#ifndef IPXP_PROCESS_TLS_HPP
#define IPXP_PROCESS_TLS_HPP

#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define TLS_UNIREC_TEMPLATE "TLS_SNI,TLS_JA3,TLS_ALPN"

UR_FIELDS(
   string TLS_SNI,
   string TLS_ALPN,
   bytes TLS_JA3
)

/**
 * \brief Flow record extension header for storing parsed HTTPS packets.
 */
struct RecordExtTLS : public RecordExt {
   static int REGISTERED_ID;

   char alpn[255];
   char sni[255];
   char ja3_hash[33];
   uint8_t ja3_hash_bin[16];
   std::string ja3;

   /**
    * \brief Constructor.
    */
   RecordExtTLS() : RecordExt(REGISTERED_ID)
   {
      alpn[0] = 0;
      sni[0] = 0;
      ja3_hash[0] = 0;
   }
#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_TLS_SNI, sni);
      ur_set_string(tmplt, record, F_TLS_ALPN, alpn);
      ur_set_var(tmplt, record, F_TLS_JA3, ja3_hash_bin, 16);
   }

   const char *get_unirec_tmplt() const
   {
      return TLS_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      int sni_len = strlen(sni);
      int alpn_len = strlen(alpn);
      int pos = 0;

      if (sni_len + alpn_len + 16 + 3 > size) {
         return -1;
      }

      buffer[pos++] = sni_len;
      memcpy(buffer + pos, sni, sni_len);
      pos += sni_len;

      buffer[pos++] = alpn_len;
      memcpy(buffer + pos, alpn, alpn_len);
      pos += alpn_len;

      buffer[pos++] = 16;
      memcpy(buffer + pos, ja3_hash_bin, 16);
      pos += 16;

      return pos;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_TLS_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };

      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "tlssni=\"" << sni << "\""
         << ",tlsalpn=\"" << alpn << "\""
         << ",tlsja3=";
      for (int i = 0; i < 16; i++) {
         out << std::hex << std::setw(2) << (unsigned) ja3_hash_bin[i];
      }
      return out.str();
   }
};


struct payload_data {
   char* data;
   const char* end;
   bool valid;
   int sni_parsed;
};

union __attribute__ ((packed)) tls_version {
   uint16_t version;
   struct {
      uint8_t major;
      uint8_t minor;
   };
};

#define TLS_HANDSHAKE 22
struct __attribute__ ((packed)) tls_rec {
   uint8_t type;
   tls_version version;
   uint16_t length;
   /* Record data... */
};

#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2
struct __attribute__ ((packed)) tls_handshake {
   uint8_t type;
   uint8_t length1; // length field is 3 bytes long...
   uint16_t length2;
   tls_version version;

   /* Handshake data... */
};

#define TLS_EXT_SERVER_NAME 0
#define TLS_EXT_ECLIPTIC_CURVES 10 // AKA supported_groups
#define TLS_EXT_EC_POINT_FORMATS 11
#define TLS_EXT_ALPN 16

struct __attribute__ ((packed)) tls_ext {
   uint16_t type;
   uint16_t length;
   /* Extension pecific data... */
};

struct __attribute__ ((packed)) tls_ext_sni {
   uint8_t type;
   uint16_t length;
   /* Hostname bytes... */
};

void get_tls_server_name(payload_data &data, char *out, size_t bufsize);
bool parse_tls_nonext_hdr(payload_data &payload, std::stringstream *ja3);

/**
 * \brief Flow cache plugin for parsing HTTPS packets.
 */
class TLSPlugin : public ProcessPlugin
{
public:
   TLSPlugin();
   ~TLSPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("tls", "Parse SNI from TLS traffic"); }
   std::string get_name() const { return "tls"; }
   RecordExtTLS *get_ext() const { return new RecordExtTLS(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish(bool print_stats);

private:
   void add_tls_record(Flow &rec, const Packet &pkt);
   bool parse_tls(const char *data, uint16_t payload_len, RecordExtTLS *rec);
   std::string get_ja3_ecpliptic_curves(payload_data &data);
   std::string get_ja3_ec_point_formats(payload_data &data);
   void get_alpn(payload_data &data, RecordExtTLS *rec);

   RecordExtTLS *ext_ptr;
   uint32_t parsed_sni;
   bool flow_flush;
};

}
#endif /* IPXP_PROCESS_TLS_HPP */
