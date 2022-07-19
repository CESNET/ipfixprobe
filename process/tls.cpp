/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2018-2022, CESNET z.s.p.o.
 */

/**
 * \file tls.cpp
 * \brief Plugin for enriching flows for tls data.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \date 2018-2022
 */


#include <iostream>
#include <sstream>

#include <stdio.h>

#include "tls.hpp"
#include "md5.hpp"

namespace ipxp {
int RecordExtTLS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("tls", [](){
         return new TLSPlugin();
      });

   register_plugin(&rec);
   RecordExtTLS::REGISTERED_ID = register_extension();
}

// Print debug message if debugging is allowed.
#ifdef DEBUG_TLS
# define DEBUG_MSG(format, ...) fprintf(stderr, format, ## __VA_ARGS__)
#else
# define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_TLS
# define DEBUG_CODE(code) code
#else
# define DEBUG_CODE(code)
#endif

TLSPlugin::TLSPlugin() : ext_ptr(nullptr), parsed_sni(0), flow_flush(false)
{ }

TLSPlugin::~TLSPlugin()
{
   close();
}

void TLSPlugin::init(const char *params)
{ }

void TLSPlugin::close()
{
   if (ext_ptr != nullptr) {
      delete ext_ptr;
      ext_ptr = nullptr;
   }
}

ProcessPlugin *TLSPlugin::copy()
{
   return new TLSPlugin(*this);
}

int TLSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   add_tls_record(rec, pkt);
   return 0;
}

int TLSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtTLS *ext = static_cast<RecordExtTLS *>(rec.get_extension(RecordExtTLS::REGISTERED_ID));

   if (ext != nullptr) {
      if (ext->alpn[0] == 0) {
         // Add ALPN from server packet
         parse_tls(pkt.payload, pkt.payload_len, ext);
      }
      return 0;
   }
   add_tls_record(rec, pkt);

   return 0;
}

bool TLSPlugin::obtain_tls_data(TLSData &payload, RecordExtTLS *rec, std::string &ja3, uint8_t hs_type)
{
   std::string ecliptic_curves;
   std::string ec_point_formats;


   while (payload.start + sizeof(tls_ext) <= payload.end) {
      tls_ext *ext    = (tls_ext *) payload.start;
      uint16_t length = ntohs(ext->length);
      uint16_t type   = ntohs(ext->type);

      payload.start += sizeof(tls_ext);
      if (payload.start + length > payload.end) {
         break;
      }

      if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
         if (type == TLS_EXT_SERVER_NAME) {
            tls_parser.tls_get_server_name(payload, rec->sni, sizeof(rec->sni));
         } else if (type == TLS_EXT_ECLIPTIC_CURVES) {
            ecliptic_curves = tls_parser.tls_get_ja3_ecpliptic_curves(payload);
         } else if (type == TLS_EXT_EC_POINT_FORMATS) {
            ec_point_formats = tls_parser.tls_get_ja3_ec_point_formats(payload);
         }
      } else if (hs_type == TLS_HANDSHAKE_SERVER_HELLO) {
         if (type == TLS_EXT_ALPN) {
            tls_parser.tls_get_alpn(payload, rec->alpn, BUFF_SIZE);
            return true;
         }
      }
      payload.start += length;
      if (!tls_parser.tls_is_grease_value(type)) {
         ja3 += std::to_string(type);

         if (payload.start + sizeof(tls_ext) <= payload.end) {
            ja3 += '-';
         }
      }
   }
   if (hs_type == TLS_HANDSHAKE_SERVER_HELLO) {
      return false;
   }
   ja3 += ',' + ecliptic_curves + ',' + ec_point_formats;
   md5_get_bin(ja3, rec->ja3_hash_bin);
   return true;
} // TLSPlugin::obtain_tls_data

bool TLSPlugin::parse_tls(const uint8_t *data, uint16_t payload_len, RecordExtTLS *rec)
{
   TLSData payload = {
      payload.start = data,
      payload.end   = data + payload_len,
      payload.obejcts_parsed = 0,
   };
   std::string ja3;


   if (!tls_parser.tls_check_rec(payload)) {
      return false;
   }
   if (!tls_parser.tls_check_handshake(payload)) {
      return false;
   }
   tls_handshake tls_hs = tls_parser.tls_get_handshake();

   rec->version = ((uint16_t) tls_hs.version.major << 8) | tls_hs.version.minor;
   ja3 += std::to_string((uint16_t) tls_hs.version.version) + ',';

   if (!tls_parser.tls_skip_random(payload)) {
      return false;
   }
   if (!tls_parser.tls_skip_sessid(payload)) {
      return false;
   }

   if (tls_hs.type == TLS_HANDSHAKE_CLIENT_HELLO) {
      if (!tls_parser.tls_get_ja3_cipher_suites(ja3, payload)) {
         return false;
      }
      if (!tls_parser.tls_skip_compression_met(payload)) {
         return false;
      }
   } else if (tls_hs.type == TLS_HANDSHAKE_SERVER_HELLO) {
      payload.start += 2; // Skip cipher suite
      payload.start += 1; // Skip compression method
   } else   {
      return false;
   }
   if (!tls_parser.tls_check_ext_len(payload)) {
      return false;
   }
   if (!obtain_tls_data(payload, rec, ja3, tls_hs.type)) {
      return false;
   }
   parsed_sni = payload.obejcts_parsed;
   return payload.obejcts_parsed != 0 || !ja3.empty();
} // TLSPlugin::parse_sni

void TLSPlugin::add_tls_record(Flow &rec, const Packet &pkt)
{
   if (ext_ptr == nullptr) {
      ext_ptr = new RecordExtTLS();
   }

   if (parse_tls(pkt.payload, pkt.payload_len, ext_ptr)) {
      DEBUG_CODE(for (int i = 0; i < 16; i++) {
            DEBUG_MSG("%02x", ext_ptr->ja3_hash_bin[i]);
         }
      )
      DEBUG_MSG("\n");
      DEBUG_MSG("%s\n", ext_ptr->sni);
      DEBUG_MSG("%s\n", ext_ptr->alpn);
      rec.add_extension(ext_ptr);
      ext_ptr = nullptr;
   }
}

void TLSPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "TLS plugin stats:" << std::endl;
      std::cout << "   Parsed SNI: " << parsed_sni << std::endl;
   }
}
}
