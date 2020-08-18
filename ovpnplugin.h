/**
 * \file ovpnplugin.h
 * \brief Plugin for parsing ovpn traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \author Martin Ctrnacty <ctrnama2@fit.cvut.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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

#ifndef OVPNDETECORPLUGIN_H
#define OVPNDETECORPLUGIN_H

#include <string>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed VPNDETECTOR packets.
 */
struct RecordExtOVPN : RecordExt
{
   uint8_t possible_vpn;
   uint32_t pkt_cnt;
   uint32_t data_pkt_cnt;
   int32_t invalid_pkt_cnt;
   uint32_t status;
   ipaddr_t client_ip;

   RecordExtOVPN() : RecordExt(ovpn)
   {
      possible_vpn = 0;
      pkt_cnt = 0;
      data_pkt_cnt = 0;
      invalid_pkt_cnt = 0;
      status = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      #ifndef DISABLE_UNIREC
      ur_set(tmplt, record, F_OVPN_CONF_LEVEL, possible_vpn);
      #endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      if (size < 1) {
         return -1;
      }
      buffer[0] = (uint8_t) possible_vpn;
      return 1;
   }
};

/**
 * \brief Flow cache plugin for parsing VPNDETECTOR packets.
 */
class OVPNPlugin : public FlowCachePlugin
{
public:
   OVPNPlugin(const options_t &module_options);
   OVPNPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void update_record(RecordExtOVPN* vpn_data, const Packet &pkt);
   void pre_export(Flow &rec);
   const char **get_ipfix_string();
   string get_unirec_field_string();

   typedef enum e_ip_proto_nbr {
      tcp = 6,
      udp = 17
   } e_ip_proto_nbr;

   static const uint32_t c_udp_opcode_index = 0;
   static const uint32_t c_tcp_opcode_index = 2;
   static const uint32_t min_pckt_treshold = 20;
   static const float data_pckt_treshold = 0.6;
   static const int32_t invalid_pckt_treshold = 4;
   static const uint32_t min_opcode = 1;
   static const uint32_t max_opcode = 10;
   static const uint32_t p_control_hard_reset_client_v1 = 1;    /* initial key from client, forget previous state */
   static const uint32_t p_control_hard_reset_server_v1 = 2;    /* initial key from server, forget previous state */
   static const uint32_t p_control_soft_reset_v1 = 3;           /* new key, graceful transition from old to new key */
   static const uint32_t p_control_v1 = 4;                      /* control channel packet (usually tls ciphertext) */
   static const uint32_t p_ack_v1 = 5;                          /* acknowledgement for packets received */
   static const uint32_t p_data_v1 = 6;                         /* data channel packet */
   static const uint32_t p_data_v2 = 9;                         /* data channel packet with peer-id */
   static const uint32_t p_control_hard_reset_client_v2 = 7;    /* initial key from client, forget previous state */
   static const uint32_t p_control_hard_reset_server_v2 = 8;    /* initial key from server, forget previous state */
   static const uint32_t p_control_hard_reset_client_v3 = 10;   /* initial key from client, forget previous state */
   static const uint32_t status_null = 0;
   static const uint32_t status_reset_client = 1;
   static const uint32_t status_reset_server = 2;
   static const uint32_t status_ack = 3;
   static const uint32_t status_client_hello = 4;
   static const uint32_t status_server_hello = 5;
   static const uint32_t status_control_ack = 6;
   static const uint32_t status_data = 7;

private:
   bool compare_ip(ipaddr_t ip_1, ipaddr_t ip_2, uint8_t ip_version);
   bool check_ssl_client_hello(const Packet &pkt, uint8_t opcodeindex);
   bool check_ssl_server_hello(const Packet &pkt, uint8_t opcodeindex);

   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif
