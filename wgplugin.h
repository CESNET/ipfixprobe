/**
 * \file wgplugin.h
 * \brief Plugin for parsing wg traffic.
 * \author Pavel Valach <valacpav@fit.cvut.cz>
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

#ifndef WGPLUGIN_H
#define WGPLUGIN_H

#include <string>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

using namespace std;


/**
 * \brief WireGuard packet types.
 */
#define WG_PACKETTYPE_INIT_TO_RESP   0x01    /**< Initiator to Responder message **/
#define WG_PACKETTYPE_RESP_TO_INIT   0x02    /**< Responder to Initiator message **/
#define WG_PACKETTYPE_COOKIE_REPLY   0x03    /**< Cookie Reply (under load) message **/
#define WG_PACKETTYPE_TRANSPORT_DATA 0x04    /**< Transport Data message **/

/**
 * \brief Flow record extension header for storing parsed WG packets.
 */
struct RecordExtWG : RecordExt {
   uint32_t src_peer;
   uint32_t dst_peer;

   RecordExtWG() : RecordExt(wg)
   {
      src_peer = 0;
      dst_peer = 0;
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_WG_SRC_PEER, src_peer);
      ur_set(tmplt, record, F_WG_DST_PEER, dst_peer);
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int requiredLen = 0;

      requiredLen += sizeof(src_peer); // WG_SRC_PEER
      requiredLen += sizeof(dst_peer); // WG_DST_PEER

      if (requiredLen > size) {
         return -1;
      }

      memcpy(buffer, &src_peer, sizeof(src_peer));
      buffer += sizeof(src_peer);
      memcpy(buffer, &dst_peer, sizeof(dst_peer));
      buffer += sizeof(dst_peer);
      
      return requiredLen;
   }
};

/**
 * \brief Flow cache plugin for parsing WG packets.
 */
class WGPlugin : public FlowCachePlugin
{
public:
   WGPlugin(const options_t &module_options);
   WGPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   bool parse_wg(const char *data, unsigned int payload_len, bool source_pkt, RecordExtWG *ext);
   int add_ext_wg(const char *data, unsigned int payload_len, bool source_pkt, Flow &rec);

   bool print_stats;       /**< Print stats when flow cache finish. */
   uint32_t total;         /**< Total number of processed packets. */
   uint32_t identified;    /**< Total number of identified WireGuard packets. */   
};


#endif

