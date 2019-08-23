/*
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

 * This software is provided ``as is'', and any express or implied
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
*/

#ifndef _HTTPS_PLUGIN_P4_
#define _HTTPS_PLUGIN_P4_

#include <core.p4>
#include "types.p4"
#include "ipfix.p4"
#include "plugin.p4"

struct https_extension_s
{
   @stringbuf("255") bit<1> sni;
}

#define TLS_HANDSHAKE 22

header tls_rec_h
{
   bit<8> type;
   bit<8> v_major;
   bit<8> v_minor;
   bit<16> length;

   // record data...
}

#define TLS_HANDSHAKE_CLIENT_HELLO 1
header tls_handshake_h
{
   bit<8> type;
   bit<24> length;
   bit<8> v_major;
   bit<8> v_minor;

   // handshake data...
}

#define TLS_EXT_SERVER_NAME 0
header tls_ext_h
{
   bit<16> type;
   bit<16> length;

   // extension specific data...
}

#define TLS_EXT_SNI_HOSTNAME 0
header tls_ext_sni_h
{
   bit<8> type;
   bit<16> length;

   // hosname bytes;
}

parser https_plugin_parser(payload p, out https_extension_s ext)
{
   tls_rec_h tls_rec;
   tls_handshake_h tls_hs;
   
   bit<16> extensions_len;
   bit<16> extensions_len_parsed;
   tls_ext_h tls_ext;

   bit<16> sni_list_len;
   bit<16> sni_list_len_parsed;
   tls_ext_sni_h tls_sni;

   state start {
      @regex("\"\x00\"") bit<1> re_empty;
      transition select(p.match(re_empty, ext.sni)) {
         true: flush;
         default: check_record;
      }
   }
   state check_record {
      p.extract(tls_rec);

      transition select(tls_rec.type) {
         TLS_HANDSHAKE: check_version_1;
         default: reject;
      }
   }
   state check_version_1 {
      transition select(tls_rec.v_major) {
         3: check_version_2;
         default: reject;
      }
   }
   state check_version_2 {
      transition select(tls_rec.v_minor) {
         0: check_hello;
         1: check_hello;
         2: check_hello;
         3: check_hello;
         default: reject;
      }
   }
   state check_hello {
      p.extract(tls_hs);
      transition select(tls_hs.type) {
         TLS_HANDSHAKE_CLIENT_HELLO: check_hello_version_1;
         default: reject;
      }
   }
   state check_hello_version_1 {
      transition select(tls_hs.v_major) {
         3: check_hello_version_2;
         default: reject;
      }
   }
   state check_hello_version_2 {
      transition select(tls_hs.v_minor) {
         1: skip_parameters;
         2: skip_parameters;
         3: skip_parameters;
         default: reject;
      }
   }
   state skip_parameters {
      bit<8> session_id_len;
      bit<16> cipher_suites_len;
      bit<8> compression_methods_len;

      p.advance(32); // skip random

      p.extract(session_id_len);
      p.advance((bit<32>) session_id_len); // skip session ID

      p.extract(cipher_suites_len);
      p.advance((bit<32>) cipher_suites_len); // skip cipher suites

      p.extract(compression_methods_len);
      p.advance((bit<32>) compression_methods_len); // skip compression methods

      p.extract(extensions_len);
      extensions_len_parsed = 0;
      transition parse_extensions_check;
   }
   state parse_extensions_check {
      transition select(extensions_len_parsed + 4 >= extensions_len) {
         true: reject;
         default: parse_extensions;
      }
   }
   state parse_extensions {
      p.extract(tls_ext);
      transition select(tls_ext.type) {
         TLS_EXT_SERVER_NAME: parse_sni_check;
         default: parse_extensions_skip;
      }
   }
   state parse_extensions_skip {
      extensions_len_parsed = extensions_len_parsed + tls_ext.length + 4;
      p.advance((bit<32>) tls_ext.length);
      transition parse_extensions_check;
   }
   state parse_sni_check {
      sni_list_len_parsed = 0;
      transition select(tls_ext.length > 2) {
         true: parse_sni_list_;
         default: reject;
      }
   }
   state parse_sni_list_ {
      p.extract(sni_list_len);
      transition parse_sni_list_check;
   }
   state parse_sni_list_check {
      transition select(sni_list_len_parsed + 3 >= sni_list_len) {
         true: reject;
         default: parse_sni_list;
      }
   }
   state parse_sni_list {
      p.extract(tls_sni);
      transition select(tls_sni.type) {
         TLS_EXT_SNI_HOSTNAME: parse_sni_list_elem_check;
         default: parse_sni_list_skip;
      }
   }
   state parse_sni_list_skip {
      p.advance((bit<32>) tls_sni.length);
      sni_list_len_parsed = sni_list_len_parsed + tls_sni.length + 3;
      transition parse_sni_list_check;
   }
   state parse_sni_list_elem_check {
      transition select(tls_sni.length > 0) {
         true: parse_sni;
         default: parse_sni_list_skip;
      }
   }
   state parse_sni {
      p.extract_string(ext.sni, (bit<32>) tls_sni.length);
      transition accept;
   }
   state flush {
      transition reject;
   }
}

control https_plugin_export(in flowrec_s flow, in https_extension_s ext, ipfix_exporter e)
{
   apply {
      FILL_IPFIX_TEMPLATE(IPFIX_TEMPLATE_IPV4_HTTPS, IPFIX_TEMPLATE_IPV6_HTTPS);
      e.add_field(ext.sni);
      e.set_finish();
   }
}

#endif
