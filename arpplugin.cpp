/**
 * \file dnsplugin.cpp
 * \brief Plugin for parsing ARP traffic.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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
 *
 */

#include <iostream>
#include <string>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <unirec/unirec.h>

#include "arpplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"

using namespace std;

//#define DEBUG_ARP

// Print debug message if debugging is allowed.
#ifdef DEBUG_ARP
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_ARP
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

#define ARP_UNIREC_TEMPLATE "ARP_HA_FORMAT,ARP_PA_FORMAT,ARP_OPCODE,ARP_SRC_HA,ARP_SRC_PA,ARP_DST_HA,ARP_DST_PA"

UR_FIELDS (
   uint16 ARP_HA_FORMAT,
   uint16 ARP_PA_FORMAT,
   uint16 ARP_OPCODE,
   bytes ARP_SRC_HA,
   bytes ARP_SRC_PA,
   bytes ARP_DST_HA,
   bytes ARP_DST_PA
)

ARPPlugin::ARPPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   requests = 0;
   replies = 0;
   total = 0;
}

ARPPlugin::ARPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   requests = 0;
   replies = 0;
   total = 0;
}

int ARPPlugin::pre_create(Packet &pkt)
{
   if (pkt.ethertype == ETH_P_ARP) {
      RecordExtARP *rec = new RecordExtARP();
      if (!parse_arp(pkt.payload, pkt.payload_length, rec)) {
         delete rec;
         return 0;
      }

      pkt.addExtension(rec);
      return EXPORT_PACKET;
   }

   return 0;
}

/*
 * \brief Parse ARP packet.
 * \param [in] data Pointer to arp payload.
 * \param [in] payload_len Length of arp payload.
 * \param [out] rec Struct where to store parsed arp packet.
 * \return True on success, false otherwise.
 */
bool ARPPlugin::parse_arp(const char *data, uint32_t payload_len, RecordExtARP *rec)
{
   struct arphdr *arp = (struct arphdr *) data;
   uint16_t opcode;
   uint8_t ha_len, pa_len;

   total++;
   DEBUG_MSG("---------- arp parser #%d ----------\n", total);
   DEBUG_MSG("Payload length:\t%u\n\n", payload_len);

   if (payload_len < sizeof(struct arphdr)) {
      DEBUG_MSG("payload length < %lu\n", sizeof(struct arphdr));
      return false;
   }

   ha_len = arp->ar_hln;
   pa_len = arp->ar_pln;
   opcode = ntohs(arp->ar_op);

   if (payload_len < (sizeof(struct arphdr) + ha_len * 2 + pa_len * 2)) {
      DEBUG_MSG("truncated pkt\n");
      return false;
   }

   if (opcode == ARPOP_REQUEST) {
      requests++;
   } else if (opcode == ARPOP_REPLY) {
       replies++;
   } else {
      DEBUG_MSG("invalid opcode: %d\n", opcode);
      return false;
   }

   /* Copy ARP fields. */
   rec->ha_type = ntohs(arp->ar_hrd);
   rec->pa_type = ntohs(arp->ar_pro);
   rec->ha_len = ha_len;
   rec->pa_len = pa_len;
   rec->opcode = opcode;

   /* Copy SRC and DST Hardware and Protocol Address*/
   data += sizeof(struct arphdr);
   memcpy(rec->src_ha, data, ha_len);
   data += ha_len;
   memcpy(rec->src_pa, data, pa_len);
   data += pa_len;
   memcpy(rec->dst_ha, data, ha_len);
   data += ha_len;
   memcpy(rec->dst_pa, data, pa_len);

   DEBUG_MSG("\tHA FORMAT:\t%u\n",    rec->ha_type);
   DEBUG_MSG("\tPA FORMAT:\t%u\n",    rec->pa_type);
   DEBUG_MSG("\tHA LENGTH:\t%u\n",    rec->ha_len);
   DEBUG_MSG("\tPA LENGTH:\t%u\n",    rec->pa_len);
   DEBUG_MSG("\tOPCODE:\t\t%u\n",     rec->opcode);
   DEBUG_CODE(
      DEBUG_MSG("\tSRC HA:\t\t");
      for (int i = 0; i < ha_len; i++) {
         DEBUG_MSG("%02x", rec->src_ha[i]);
      }
      DEBUG_MSG("\n\tSRC PA:\t\t");
      for (int i = 0; i < pa_len; i++) {
         DEBUG_MSG("%02x", rec->src_pa[i]);
      }
      DEBUG_MSG("\n\tDST HA:\t\t");
      for (int i = 0; i < ha_len; i++) {
         DEBUG_MSG("%02x", rec->dst_ha[i]);
      }
      DEBUG_MSG("\n\tDST PA:\t\t");
      for (int i = 0; i < pa_len; i++) {
         DEBUG_MSG("%02x", rec->dst_pa[i]);
      }
      DEBUG_MSG("\n");
   );

   return true;
}

void ARPPlugin::finish()
{
   if (print_stats) {
      cout << "ARP plugin stats:" << endl;
      cout << "   Parsed arp requests: " << requests << endl;
      cout << "   Parsed arp replies: " << replies << endl;
      cout << "   Total arp packets processed: " << total << endl;
   }
}

string ARPPlugin::get_unirec_field_string()
{
   return ARP_UNIREC_TEMPLATE;
}

const char *ipfix_arp_fields[] = {
   IPFIX_ARP_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **ARPPlugin::get_ipfix_string()
{
   return ipfix_arp_fields;
}

bool ARPPlugin::include_basic_flow_fields()
{
   return false;
}

