/**
 * \file tlsplugin.h
 * \brief Plugin for parsing https traffic.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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

#ifndef TLSPLUGIN_H
#define TLSPLUGIN_H

#include <string>
#include <cstring>
#include <arpa/inet.h>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed HTTPS packets.
 */
struct RecordExtTLS : RecordExt {
   char alpn[255];
   char sni[255];
   char ja3_hash[33];
   uint8_t ja3_hash_bin[16];
   string ja3;

   /**
    * \brief Constructor.
    */
   RecordExtTLS() : RecordExt(tls)
   {
      alpn[0] = 0;
      sni[0] = 0;
      ja3_hash[0] = 0;
   }
#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_TLS_SNI, sni);
      ur_set_string(tmplt, record, F_TLS_ALPN, alpn);
      ur_set_var(tmplt, record, F_TLS_JA3, ja3_hash_bin, 16);
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
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

/**
 * \brief Flow cache plugin for parsing HTTPS packets.
 */
class TLSPlugin : public FlowCachePlugin
{
public:
   TLSPlugin(const options_t &module_options);
   TLSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   ~TLSPlugin();
   FlowCachePlugin *copy();
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();

private:
   void add_tls_record(Flow &rec, const Packet &pkt);
   bool parse_tls(const char *data, int payload_len, RecordExtTLS *rec);
   void get_ja3_cipher_suites(stringstream &ja3, payload_data &data);
   string get_ja3_ecpliptic_curves(payload_data &data);
   string get_ja3_ec_point_formats(payload_data &data);
   void get_tls_server_name(payload_data &data, RecordExtTLS *rec);
   void get_alpn(payload_data &data, RecordExtTLS *rec);
   bool is_grease_value(uint16_t val);

   RecordExtTLS *ext_ptr;
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t parsed_sni;
   bool flow_flush;
};

#endif
