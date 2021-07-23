/**
 * \file unirecexporter.cpp
 * \brief Flow exporter converting flows to UniRec and sending them to TRAP ifc
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
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

#include <config.h>

#ifdef WITH_NEMEA

#include <string>
#include <vector>
#include <algorithm>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "unirecexporter.h"
#include "fields.h"
#include "flowexporter.h"
#include "flowifc.h"
#include "ipfixprobe.h"

using namespace std;

#define BASIC_FLOW_TEMPLATE "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,PACKETS_REV,BYTES_REV,TIME_FIRST,TIME_LAST,TCP_FLAGS,TCP_FLAGS_REV,DIR_BIT_FIELD,SRC_MAC,DST_MAC" /* LINK_BIT_FIELD or ODID will be added at init. */

#define PACKET_TEMPLATE "SRC_MAC,DST_MAC,ETHERTYPE,TIME"

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 BYTES_REV,
   uint64 LINK_BIT_FIELD,
   uint32 ODID,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 PACKETS,
   uint32 PACKETS_REV,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 DIR_BIT_FIELD,
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,
   uint8 TCP_FLAGS_REV,

   macaddr SRC_MAC,
   macaddr DST_MAC,
   uint16 ETHERTYPE
   time TIME,
)

/**
 * \brief Constructor.
 */
UnirecExporter::UnirecExporter(bool send_eof) : out_ifc_cnt(0), ifc_mapping(NULL),
   tmplts(NULL), records(NULL), eof(send_eof), send_odid(false), dir_bit_field(0)
{
   flows_seen = 0;
   flows_dropped = 0;
}

UnirecExporter::~UnirecExporter()
{
   close();
}

/**
 * \brief Initialize exporter.
 * \param [in] plugins Active plugins.
 * \param [in] ifc_cnt Output interface count.
 * \param [in] basic_ifc_num Basic output interface number.
 * \param [in] link Link bit field value.
 * \param [in] dir Direction bit field value.
 * \param [in] odid Send ODID field instead of LINK_BIT_FIELD.
 * \return 0 on success or negative value when error occur.
 */
int UnirecExporter::init(const vector<FlowCachePlugin *> &plugins, int ifc_cnt, int basic_ifc_number, uint64_t link = 0, uint8_t dir = 0, bool odid = false)
{
   string basic_tmplt = BASIC_FLOW_TEMPLATE;

   out_ifc_cnt = ifc_cnt;
   basic_ifc_num = basic_ifc_number;
   link_bit_field = link;
   dir_bit_field = dir;
   send_odid = odid;

   tmplts = new ur_template_t*[out_ifc_cnt];
   records = new void*[out_ifc_cnt];

   for (int i = 0; i < out_ifc_cnt; i++) {
      tmplts[i] = NULL;
      records[i] = NULL;
   }

   if (odid) {
      basic_tmplt += ",ODID";
   } else {
      basic_tmplt += ",LINK_BIT_FIELD";
   }

   char *error = NULL;
   if (basic_ifc_num >= 0) {
      tmplts[basic_ifc_num] = ur_create_output_template(basic_ifc_num, basic_tmplt.c_str(), &error);
      if (tmplts[basic_ifc_num] == NULL) {
         fprintf(stderr, "UnirecExporter: %s\n", error);
         free(error);
         free_unirec_resources();
         return -2;
      }
   }

   ifc_mapping = new int[EXTENSION_CNT];
   for (int i = 0; i < EXTENSION_CNT; i++) {
      ifc_mapping[i] = -1;
   }

   string template_str;
   for (unsigned int i = 0; i < plugins.size(); i++) {
      FlowCachePlugin * const tmp = plugins[i];
      const vector<plugin_opt> &opts = tmp->get_options();
      int ifc = -1;

      for (unsigned int j = 0; j < opts.size(); j++) { // Create plugin extension id -> output interface mapping.
         ifc_mapping[opts[j].ext_type] = opts[j].out_ifc_num;
         ifc = opts[j].out_ifc_num;
      }

      if (opts.size() == 0 || ifc < 0) {
         continue;
      }

      // Create unirec templates.
      template_str = tmp->get_unirec_field_string() + string(",") + basic_tmplt;

      tmplts[ifc] = ur_create_output_template(ifc, template_str.c_str(), &error);
      if (tmplts[ifc] == NULL) {
         fprintf(stderr, "UnirecExporter: %s\n", error);
         free(error);
         free_unirec_resources();
         return -2;
      }
   }

   for (int i = 0; i < out_ifc_cnt; i++) { // Create unirec records.
      if (tmplts[i] != NULL) {
         records[i] = ur_create_record(tmplts[i], (i == basic_ifc_num ? 0 : UR_MAX_SIZE));

         if (records[i] == NULL) {
            free_unirec_resources();
            return -3;
         }
      }
   }

   return 0;
}

/**
 * \brief Close connection and free resources.
 */
void UnirecExporter::close()
{
   if (eof) {
      for (int i = 0; i < out_ifc_cnt; i++) {
         trap_send(i, "", 1);
      }
   }
   trap_finalize();

   free_unirec_resources();

   basic_ifc_num = -1;
   out_ifc_cnt = 0;
}

/**
 * \brief Free unirec templates and unirec records.
 */
void UnirecExporter::free_unirec_resources()
{
   if (tmplts) {
      for (int i = 0; i < out_ifc_cnt; i++) {
         if (tmplts[i] != NULL) {
            ur_free_template(tmplts[i]);
         }
      }
      delete [] tmplts;
      tmplts = NULL;
   }
   if (records) {
      for (int i = 0; i < out_ifc_cnt; i++) {
         if (records[i] != NULL) {
            ur_free_record(records[i]);
         }
      }
      delete [] records;
      records = NULL;
   }
   if (ifc_mapping) {
      delete [] ifc_mapping;
      ifc_mapping = NULL;
   }
}

int UnirecExporter::export_packet(Packet &pkt)
{
   RecordExt *ext = pkt.exts;
   ur_template_t *tmplt_ptr = NULL;
   void *record_ptr = NULL;

   while (ext != NULL) {
      flows_seen++;
      int ifc_num = ifc_mapping[ext->extType];
      if (ifc_num >= 0) {
         tmplt_ptr = tmplts[ifc_num];
         record_ptr = records[ifc_num];

         ur_clear_varlen(tmplt_ptr, record_ptr);
         memset(record_ptr, 0, ur_rec_fixlen_size(tmplt_ptr));
         fill_packet_fields(pkt, tmplt_ptr, record_ptr);
         ext->fillUnirec(tmplt_ptr, record_ptr); /* Add each extension header into unirec record. */

         trap_send(ifc_num, record_ptr, ur_rec_fixlen_size(tmplt_ptr) + ur_rec_varlen_size(tmplt_ptr, record_ptr));
      }
      ext = ext->next;
   }

   return 0;
}

int UnirecExporter::export_flow(Flow &flow)
{
   RecordExt *ext = flow.exts;
   ur_template_t *tmplt_ptr = NULL;
   void *record_ptr = NULL;

   if (basic_ifc_num >= 0) { // Process basic flow.
      tmplt_ptr = tmplts[basic_ifc_num];
      record_ptr = records[basic_ifc_num];

      ur_clear_varlen(tmplt_ptr, record_ptr);

      fill_basic_flow(flow, tmplt_ptr, record_ptr);

      trap_send(basic_ifc_num, record_ptr, ur_rec_fixlen_size(tmplt_ptr) + ur_rec_varlen_size(tmplt_ptr, record_ptr));
   }

   while (ext != NULL) {
      flows_seen++;
      int ifc_num = ifc_mapping[ext->extType];
      if (ifc_num >= 0) {
         tmplt_ptr = tmplts[ifc_num];
         record_ptr = records[ifc_num];

         ur_clear_varlen(tmplt_ptr, record_ptr);
         memset(record_ptr, 0, ur_rec_fixlen_size(tmplt_ptr));

         fill_basic_flow(flow, tmplt_ptr, record_ptr);
         ext->fillUnirec(tmplt_ptr, record_ptr); /* Add each extension header into unirec record. */

         trap_send(ifc_num, record_ptr, ur_rec_fixlen_size(tmplt_ptr) + ur_rec_varlen_size(tmplt_ptr, record_ptr));
      }
      ext = ext->next;
   }

   return 0;
}

/**
 * \brief Fill record with basic flow fields.
 * \param [in] flow Flow record.
 * \param [in] tmplt_ptr Pointer to unirec template.
 * \param [out] record_ptr Pointer to unirec record.
 */
void UnirecExporter::fill_basic_flow(Flow &flow, ur_template_t *tmplt_ptr, void *record_ptr)
{
   ur_time_t tmp_time;

   if (flow.ip_version == 4) {
      ur_set(tmplt_ptr, record_ptr, F_SRC_IP, ip_from_4_bytes_be((char *) &flow.src_ip.v4));
      ur_set(tmplt_ptr, record_ptr, F_DST_IP, ip_from_4_bytes_be((char *) &flow.dst_ip.v4));
   } else {
      ur_set(tmplt_ptr, record_ptr, F_SRC_IP, ip_from_16_bytes_be((char *) flow.src_ip.v6));
      ur_set(tmplt_ptr, record_ptr, F_DST_IP, ip_from_16_bytes_be((char *) flow.dst_ip.v6));
   }

   tmp_time = ur_time_from_sec_usec(flow.time_first.tv_sec, flow.time_first.tv_usec);
   ur_set(tmplt_ptr, record_ptr, F_TIME_FIRST, tmp_time);

   tmp_time = ur_time_from_sec_usec(flow.time_last.tv_sec, flow.time_last.tv_usec);
   ur_set(tmplt_ptr, record_ptr, F_TIME_LAST, tmp_time);

   if (send_odid) {
      ur_set(tmplt_ptr, record_ptr, F_ODID, link_bit_field);
   } else {
      ur_set(tmplt_ptr, record_ptr, F_LINK_BIT_FIELD, link_bit_field);
   }
   ur_set(tmplt_ptr, record_ptr, F_DIR_BIT_FIELD, dir_bit_field);
   ur_set(tmplt_ptr, record_ptr, F_PROTOCOL, flow.ip_proto);
   ur_set(tmplt_ptr, record_ptr, F_SRC_PORT, flow.src_port);
   ur_set(tmplt_ptr, record_ptr, F_DST_PORT, flow.dst_port);
   ur_set(tmplt_ptr, record_ptr, F_PACKETS, flow.src_pkt_total_cnt);
   ur_set(tmplt_ptr, record_ptr, F_BYTES, flow.src_octet_total_length);
   ur_set(tmplt_ptr, record_ptr, F_TCP_FLAGS, flow.src_tcp_control_bits);
   ur_set(tmplt_ptr, record_ptr, F_PACKETS_REV, flow.dst_pkt_total_cnt);
   ur_set(tmplt_ptr, record_ptr, F_BYTES_REV, flow.dst_octet_total_length);
   ur_set(tmplt_ptr, record_ptr, F_TCP_FLAGS_REV, flow.dst_tcp_control_bits);

   ur_set(tmplt_ptr, record_ptr, F_DST_MAC, mac_from_bytes(flow.dst_mac));
   ur_set(tmplt_ptr, record_ptr, F_SRC_MAC, mac_from_bytes(flow.src_mac));
}


/**
 * \brief Fill record with basic flow fields.
 * \param [in] flow Flow record.
 * \param [in] tmplt_ptr Pointer to unirec template.
 * \param [out] record_ptr Pointer to unirec record.
 */
void UnirecExporter::fill_packet_fields(Packet &pkt, ur_template_t *tmplt_ptr, void *record_ptr)
{
   ur_time_t tmp_time = ur_time_from_sec_usec(pkt.timestamp.tv_sec, pkt.timestamp.tv_usec);

   ur_set(tmplt_ptr, record_ptr, F_DST_MAC, mac_from_bytes((uint8_t *) pkt.packet));
   ur_set(tmplt_ptr, record_ptr, F_SRC_MAC, mac_from_bytes((uint8_t *) pkt.packet + 6));
   ur_set(tmplt_ptr, record_ptr, F_ETHERTYPE, pkt.ethertype);
   ur_set(tmplt_ptr, record_ptr, F_TIME, tmp_time);
}

#endif

