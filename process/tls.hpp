/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2018-2022, CESNET z.s.p.o.
 */

/**
 * \file tls.hpp
 * \brief Plugin for enriching flows for tls data.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * \date 2022
 */


#ifndef IPXP_PROCESS_TLS_HPP
#define IPXP_PROCESS_TLS_HPP

#include <string>
#include <cstring>
#include <arpa/inet.h>

#include <sstream>
#include <iomanip>

#ifdef WITH_NEMEA
# include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/utils.hpp>
#include <process/tls_parser.hpp>


#define BUFF_SIZE 255

namespace ipxp {
#define TLS_UNIREC_TEMPLATE "TLS_SNI,TLS_JA3,TLS_ALPN,TLS_VERSION,TLS_EXT_TYPE,TLS_EXT_LEN"

UR_FIELDS(
   string TLS_SNI,
   string TLS_ALPN,
   uint16 TLS_VERSION,
   bytes TLS_JA3,
   uint16* TLS_EXT_TYPE,
   uint16* TLS_EXT_LEN
)

/**
 * \brief Flow record extension header for storing parsed HTTPS packets.
 */
// TODO fix IEs
#define TLS_EXT_TYPE_FIELD_ID 802
#define TLS_EXT_LEN_FIELD_ID 803
struct RecordExtTLS : public RecordExt {
   static int  REGISTERED_ID;

   uint16_t    version;
   char        alpn[BUFF_SIZE]  = { 0 };
   char        sni[BUFF_SIZE]   = { 0 };
   char        ja3_hash[33]     = { 0 };
   uint8_t     ja3_hash_bin[16] = { 0 };
   std::string ja3;
   bool        server_hello_parsed;

   uint16_t tls_ext_type[MAX_TLS_EXT_LEN];
   uint16_t tls_ext_type_len;
   bool tls_ext_type_set;

   uint16_t tls_ext_len[MAX_TLS_EXT_LEN];
   uint8_t tls_ext_len_len;
   bool tls_ext_len_set;

   /**
    * \brief Constructor.
    */
   RecordExtTLS() : RecordExt(REGISTERED_ID), version(0)
   {
      alpn[0]     = 0;
      sni[0]      = 0;
      ja3_hash[0] = 0;
      server_hello_parsed = false;

      memset(tls_ext_type, 0, sizeof(tls_ext_type));
      tls_ext_type_len = 0;
      tls_ext_type_set = false;

      memset(tls_ext_len, 0, sizeof(tls_ext_len));
      tls_ext_len_len = 0;
      tls_ext_len_set = false;
   }

   #ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_TLS_VERSION, version);
      ur_set_string(tmplt, record, F_TLS_SNI, sni);
      ur_set_string(tmplt, record, F_TLS_ALPN, alpn);
      ur_set_var(tmplt, record, F_TLS_JA3, ja3_hash_bin, 16);
      ur_array_allocate(tmplt, record, F_QUIC_TLS_EXT_TYPE, tls_ext_type_len);
      for (int i = 0; i < tls_ext_type_len; i++) {
          ur_array_set(tmplt, record, F_TLS_EXT_TYPE, i, tls_ext_type[i]);
      }
      ur_array_allocate(tmplt, record, F_TLS_EXT_LEN, tls_ext_len_len);
      for (int i = 0; i < tls_ext_len_len; i++) {
          ur_array_set(tmplt, record, F_TLS_EXT_LEN, i, tls_ext_len[i]);
      }
   }

   const char *get_unirec_tmplt() const
   {
      return TLS_UNIREC_TEMPLATE;
   }

   #endif // ifdef WITH_NEMEA

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      IpfixBasicList basiclist;

      uint16_t sni_len  = strlen(sni);
      uint16_t alpn_len = strlen(alpn);

      uint32_t pos = 0;

      uint16_t len_tls_ext_type = sizeof(tls_ext_type[0]) * (tls_ext_type_len) + basiclist.HeaderSize();
      uint16_t len_tls_len = sizeof(tls_ext_len[0]) * (tls_ext_len_len) + basiclist.HeaderSize();

      uint32_t req_buff_len = (sni_len + 3) + (alpn_len + 3) + (2) + (16 + 3) + len_tls_ext_type + len_tls_len; // (SNI) + (ALPN) + (VERSION) + (JA3)

      if (req_buff_len > (uint32_t) size) {
         return -1;
      }

      *(uint16_t *) buffer = ntohs(version);
      pos += 2;

      pos += variable2ipfix_buffer(buffer + pos, (uint8_t *) sni, sni_len);
      pos += variable2ipfix_buffer(buffer + pos, (uint8_t *) alpn, alpn_len);

      buffer[pos++] = 16;
      memcpy(buffer + pos, ja3_hash_bin, 16);
      pos += 16;
      pos += basiclist.FillBuffer(
                    buffer + pos,
                    tls_ext_type,
                    (uint16_t) tls_ext_type_len,
                    (uint16_t) TLS_EXT_TYPE_FIELD_ID);
      pos += basiclist.FillBuffer(
            buffer + pos,
            tls_ext_len,
            (uint16_t) tls_ext_len_len,
            (uint16_t) TLS_EXT_LEN_FIELD_ID);
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
          << ",tlsversion=0x" << std::hex << std::setw(4) << std::setfill('0') << version
          << ",tlsja3=";
      for (int i = 0; i < 16; i++) {
         out << std::hex << std::setw(2) << std::setfill('0') << (unsigned) ja3_hash_bin[i];
      }
      out << ",tlsexttype=(";
              for (int i = 0; i < tls_ext_type_len; i++) {
                  out << std::dec << (uint16_t) tls_ext_type[i];
                  if (i != tls_ext_type_len - 1) {
                      out << ",";
                  }
              }
      out << "),tlsextlen=(";
      for (int i = 0; i < tls_ext_len_len; i++) {
          out << std::dec << (uint16_t) tls_ext_len[i];
          if (i != tls_ext_len_len - 1) {
              out << ",";
          }
      }
      out << ")";

      return out.str();
   }
};


#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2


#define TLS_EXT_SERVER_NAME      0
#define TLS_EXT_ECLIPTIC_CURVES  10 // AKA supported_groups
#define TLS_EXT_EC_POINT_FORMATS 11
#define TLS_EXT_ALPN             16
#define TLS_EXT_SUPPORTED_VER    43


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
   void add_tls_record(Flow&, const Packet&);
   bool parse_tls(const uint8_t *, uint16_t, RecordExtTLS *);
   bool obtain_tls_data(TLSData&, RecordExtTLS *, std::string&, uint8_t);

   RecordExtTLS *ext_ptr;
   TLSParser tls_parser;
   uint32_t parsed_sni;
   bool flow_flush;
};
}
#endif /* IPXP_PROCESS_TLS_HPP */
