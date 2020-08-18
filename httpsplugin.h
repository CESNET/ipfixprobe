/**
 * \file httpsplugin.h
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

#ifndef HTTPSPLUGIN_H
#define HTTPSPLUGIN_H

#include <string>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed HTTPS packets.
 */
struct RecordExtHTTPS : RecordExt {
   char sni[255];

   /**
    * \brief Constructor.
    */
   RecordExtHTTPS() : RecordExt(https)
   {
      sni[0] = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_set_string(tmplt, record, F_HTTPS_SNI, sni);
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int len = strlen(sni);

      if (len + 1 > size) {
         return -1;
      }

      buffer[0] = len;
      memcpy(buffer + 1, sni, len);

      return len + 1;
   }
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
struct __attribute__ ((packed)) tls_handshake {
   uint8_t type;
   uint8_t length1; // length field is 3 bytes long...
   uint16_t length2;
   tls_version version;

   /* Handshake data... */
};

#define TLS_EXT_SERVER_NAME 0
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
class HTTPSPlugin : public FlowCachePlugin
{
public:
   HTTPSPlugin(const options_t &module_options);
   HTTPSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   ~HTTPSPlugin();
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   void add_https_record(Flow &rec, const Packet &pkt);
   bool parse_sni(const char *data, int payload_len, RecordExtHTTPS *rec);

   RecordExtHTTPS *ext_ptr;
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t total;
   uint32_t parsed_sni;
   bool flow_flush;
};

#endif

