/**
 * \file dnsplugin.h
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

#ifndef ARPPLUGIN_H
#define ARPPLUGIN_H

#include <string>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed ARP packets.
 */
struct RecordExtARP : RecordExt {
   uint16_t ha_type;    /**< Hardware address type. */
   uint16_t pa_type;    /**< Protocol address type. */
   uint8_t ha_len;      /**< Hardware address length. */
   uint8_t pa_len;      /**< Protocol address length. */
   uint16_t opcode;     /**< Operation code. */
   uint8_t src_ha[254]; /**< Source hardware address. */
   uint8_t src_pa[254]; /**< Source protocol address. */
   uint8_t dst_ha[254]; /**< Destination hardware address. */
   uint8_t dst_pa[254]; /**< Destination protocol address. */

   /**
    * \brief Constructor.
    */
   RecordExtARP() : RecordExt(arp), ha_len(0), pa_len(0)
   {
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_set(tmplt, record, F_ARP_HA_FORMAT, ha_type);
      ur_set(tmplt, record, F_ARP_PA_FORMAT, pa_type);
      ur_set(tmplt, record, F_ARP_OPCODE, opcode);
      ur_set_var(tmplt, record, F_ARP_SRC_HA, src_ha, ha_len);
      ur_set_var(tmplt, record, F_ARP_SRC_PA, src_pa, pa_len);
      ur_set_var(tmplt, record, F_ARP_DST_HA, dst_ha, ha_len);
      ur_set_var(tmplt, record, F_ARP_DST_PA, dst_pa, pa_len);
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int total_length = 6;

      if (total_length + 2 * ha_len + 2 * pa_len + 4 > size) {
         return -1;
      }

      *(uint16_t *) (buffer) = ntohs(ha_type);
      *(uint16_t *) (buffer + 2) = ntohs(pa_type);
      *(uint16_t *) (buffer + 4) = ntohs(opcode);

      buffer[total_length] = ha_len;
      memcpy(buffer + total_length + 1, src_ha, ha_len);
      total_length += ha_len + 1;

      buffer[total_length] = pa_len;
      memcpy(buffer + total_length + 1, src_pa, pa_len);
      total_length += pa_len + 1;

      buffer[total_length] = ha_len;
      memcpy(buffer + total_length + 1, dst_ha, ha_len);
      total_length += ha_len + 1;

      buffer[total_length] = pa_len;
      memcpy(buffer + total_length + 1, dst_pa, pa_len);
      total_length += pa_len + 1;

      return total_length;
   }
};

/**
 * \brief Flow cache plugin for parsing ARP packets.
 */
class ARPPlugin : public FlowCachePlugin
{
public:
   ARPPlugin(const options_t &module_options);
   ARPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int pre_create(Packet &pkt);
   void finish();
   string get_unirec_field_string();
   const char **get_ipfix_string();
   bool include_basic_flow_fields();

private:
   bool parse_arp(const char *data, uint32_t payload_len, RecordExtARP *rec);

   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t requests;      /**< Total number of parsed ARP requests. */
   uint32_t replies;       /**< Total number of parsed ARP replies. */
   uint32_t total;         /**< Total number of parsed ARP packets. */
};

#endif
