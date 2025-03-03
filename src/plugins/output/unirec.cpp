/**
 * \file unirec.cpp
 * \brief Flow exporter converting flows to UniRec and sending them to TRAP ifc
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
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
 *
 *
 */

#include <config.h>

#ifdef WITH_NEMEA

#include <string>
#include <vector>
#include <algorithm>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "unirec.hpp"
#include "fields.h"

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("unirec", [](){return new UnirecExporter();});
   register_plugin(&rec);
}

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
   macaddr DST_MAC
)

/**
 * \brief Constructor.
 */
UnirecExporter::UnirecExporter() : m_basic_idx(-1), m_ext_cnt(0),
   m_ifc_map(nullptr), m_tmplts(nullptr), m_records(nullptr), m_ifc_cnt(0),
   m_ext_id_flgs(nullptr), m_eof(false), m_odid(false), m_link_bit_field(0),
   m_dir_bit_field(0)
{
}

UnirecExporter::~UnirecExporter()
{
   close();
}

/**
 * \brief Count trap interfaces.
 * \param [in] argc Number of parameters.
 * \param [in] argv Pointer to parameters.
 * \return Number of trap interfaces.
 */
static int count_trap_interfaces(const char *spec)
{
   int ifc_cnt = 1;
   if (spec != nullptr) {
      while(*spec) { // Count number of specified interfaces.
         if (*(spec++) == TRAP_IFC_DELIMITER) {
            ifc_cnt++;
         }
      }
      return ifc_cnt;
   }

   return ifc_cnt;
}

int UnirecExporter::init_trap(std::string &ifcs, int verbosity)
{
   trap_ifc_spec_t ifc_spec;
   std::vector<char> spec_str(ifcs.c_str(), ifcs.c_str() + ifcs.size() + 1);
   char *argv[] = {"-i", spec_str.data()};
   int argc = 2;
   int ifc_cnt = count_trap_interfaces(ifcs.c_str());

   if (trap_parse_params(&argc, argv, &ifc_spec) != TRAP_E_OK) {
      trap_free_ifc_spec(ifc_spec);
      std::string err_msg = "parsing parameters for TRAP failed";
      if (trap_last_error_msg) {
         err_msg += std::string(": ") + trap_last_error_msg;
      }
      throw PluginError(err_msg);
   }
   trap_module_info_t module_info = {"ipfixprobe", "Output plugin for ipfixprobe", 0, ifc_cnt};
   if (trap_init(&module_info, ifc_spec) != TRAP_E_OK) {
      trap_free_ifc_spec(ifc_spec);
      std::string err_msg = "error in TRAP initialization: ";
      if (trap_last_error_msg) {
         err_msg += std::string(": ") + trap_last_error_msg;
      }
      throw PluginError(err_msg);
   }
   trap_free_ifc_spec(ifc_spec);

   if (verbosity > 0) {
      trap_set_verbose_level(verbosity - 1);
   }
   for (int i = 0; i < ifc_cnt; i++) {
      trap_ifcctl(TRAPIFC_OUTPUT, i, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
   }
   return ifc_cnt;
}

void UnirecExporter::init(const char *params)
{
   UnirecOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   if (parser.m_help) {
      trap_print_ifc_spec_help();
      throw PluginExit();
   }
   if (parser.m_ifc.empty()) {
      throw PluginError("specify libtrap interface specifier");
   }
   m_odid = parser.m_odid;
   m_eof = parser.m_eof;
   m_link_bit_field = parser.m_id;
   m_dir_bit_field = parser.m_dir;
   m_group_map = parser.m_ifc_map;
   m_ifc_cnt = init_trap(parser.m_ifc, parser.m_verbose);
   m_ext_cnt = get_extension_cnt();

   try {
      m_tmplts = new ur_template_t*[m_ifc_cnt];
      m_records = new void*[m_ifc_cnt];
      m_ifc_map = new int[m_ext_cnt];
      m_ext_id_flgs = new int[m_ext_cnt];
   } catch (std::bad_alloc &e) {
      throw PluginError("not enough memory");
   }
   for (size_t i = 0; i < m_ifc_cnt; i++) {
      m_tmplts[i] = nullptr;
      m_records[i] = nullptr;
   }
   for (size_t i = 0; i < m_ext_cnt; i++) {
      m_ifc_map[i] = -1;
   }
}

void UnirecExporter::create_tmplt(int ifc_idx, const char *tmplt_str)
{
   char *error = nullptr;
   m_tmplts[ifc_idx] = ur_create_output_template(ifc_idx, tmplt_str, &error);
   if (m_tmplts[ifc_idx] == nullptr) {
      std::string tmp = error;
      free(error);
      free_unirec_resources();
      throw PluginError(tmp);
   }
}

void UnirecExporter::init(const char *params, Plugins &plugins)
{
   init(params);

   std::string basic_tmplt = BASIC_FLOW_TEMPLATE;
   if (m_odid) {
      basic_tmplt += ",ODID";
   } else {
      basic_tmplt += ",LINK_BIT_FIELD";
   }

   if (m_group_map.empty()) {
      if (m_ifc_cnt == 1 && plugins.empty()) {
         m_basic_idx = 0;

         create_tmplt(m_basic_idx, basic_tmplt.c_str());
      } else if (m_ifc_cnt == 1 && plugins.size() == 1) {
         m_group_map[0] = std::vector<std::string>({plugins[0].first});
      } else {
         throw PluginError("specify plugin-interface mapping");
      }
   }

   if (m_ifc_cnt != 1 && m_ifc_cnt != m_group_map.size()) {
      throw PluginError("number of interfaces and plugin groups differ");
   }

   for (auto &m : m_group_map) {
      unsigned ifc_idx = m.first;
      std::vector<std::string> &group = m.second;

      // Find plugin for each plugin in group
      std::vector<ProcessPlugin *> plugin_group;
      for (auto &g : group) {
         ProcessPlugin *plugin = nullptr;
         for (auto &p : plugins) {
            std::string name = p.first;
            if (g == name) {
               plugin = p.second;
               break;
            }
         }
         if (m_tmplts[ifc_idx] != nullptr || (m_basic_idx >= 0 && g == BASIC_PLUGIN_NAME)) {
            throw PluginError("plugin can be specified only one time");
         }
         if (group.size() == 1 && g == BASIC_PLUGIN_NAME) {
            m_basic_idx = ifc_idx;
            break;
         }
         if (plugin == nullptr) {
            throw PluginError(g + " plugin is not activated");
         }
         plugin_group.push_back(plugin);
      }

      // Create output template string and extension->ifc map
      std::string tmplt_str = basic_tmplt;
      for (auto &p : plugin_group) {
         RecordExt *ext = p->get_ext();
         tmplt_str += std::string(",") + ext->get_unirec_tmplt();
         int ext_id = ext->m_ext_id;
         delete ext;
         if (ext_id < 0) {
            continue;
         }
         if (m_ifc_map[ext_id] >= 0) {
            throw PluginError("plugin output can be exported only to one interface at the moment");
         }
         m_ifc_map[ext_id] = ifc_idx;
      }

      create_tmplt(ifc_idx, tmplt_str.c_str());
   }

   for (size_t i = 0; i < m_ifc_cnt; i++) { // Create unirec records.
      m_records[i] = ur_create_record(m_tmplts[i], (static_cast<ssize_t>(i) == m_basic_idx ? 0 : UR_MAX_SIZE));

      if (m_records[i] == nullptr) {
         free_unirec_resources();
         throw PluginError("not enough memory");
      }
   }

   m_group_map.clear();
}

void UnirecExporter::close()
{
   if (m_eof) {
      for (size_t i = 0; i < m_ifc_cnt; i++) {
         trap_send(i, "", 1);
      }
   }
   trap_finalize();
   free_unirec_resources();

   m_basic_idx = -1;
   m_ifc_cnt = 0;
   delete [] m_ext_id_flgs;
}

/**
 * \brief Free unirec templates and unirec records.
 */
void UnirecExporter::free_unirec_resources()
{
   if (m_tmplts) {
      for (size_t i = 0; i < m_ifc_cnt; i++) {
         if (m_tmplts[i] != nullptr) {
            ur_free_template(m_tmplts[i]);
         }
      }
      delete [] m_tmplts;
      m_tmplts = nullptr;
   }
   if (m_records) {
      for (size_t i = 0; i < m_ifc_cnt; i++) {
         if (m_records[i] != nullptr) {
            ur_free_record(m_records[i]);
         }
      }
      delete [] m_records;
      m_records = nullptr;
   }
   if (m_ifc_map) {
      delete [] m_ifc_map;
      m_ifc_map = nullptr;
   }
}

int UnirecExporter::export_flow(const Flow &flow)
{
   RecordExt *ext = flow.m_exts;
   ur_template_t *tmplt_ptr = nullptr;
   void *record_ptr = nullptr;

   if (m_basic_idx >= 0) { // Process basic flow.
      tmplt_ptr = m_tmplts[m_basic_idx];
      record_ptr = m_records[m_basic_idx];

      ur_clear_varlen(tmplt_ptr, record_ptr);
      fill_basic_flow(flow, tmplt_ptr, record_ptr);
      trap_send(m_basic_idx, record_ptr, ur_rec_fixlen_size(tmplt_ptr) + ur_rec_varlen_size(tmplt_ptr, record_ptr));
   }

   m_flows_seen++;
   uint64_t tmplt_dbits = 0; // templates dirty bits
   memset(m_ext_id_flgs, 0, sizeof(int) * m_ext_cnt); // in case one flow has multiple extension of same type
   int ext_processed_cnd = 0;
   while (ext != nullptr) {
      if (ext->m_ext_id >= static_cast<int>(m_ext_cnt)) {
         throw PluginError("encountered invalid extension id");
      }
      ext_processed_cnd++;
      int ifc_num = m_ifc_map[ext->m_ext_id];
      if (ifc_num >= 0) {
         tmplt_ptr = m_tmplts[ifc_num];
         record_ptr = m_records[ifc_num];

         if ((tmplt_dbits & (1 << ifc_num)) == 0) {
            ur_clear_varlen(tmplt_ptr, record_ptr);
            memset(record_ptr, 0, ur_rec_fixlen_size(tmplt_ptr));
            tmplt_dbits |= (1 << ifc_num);
         }

         if (m_ext_id_flgs[ext->m_ext_id] == 1) {
            // send the previously filled unirec record
            trap_send(ifc_num, record_ptr, ur_rec_size(tmplt_ptr, record_ptr));
         } else {
            m_ext_id_flgs[ext->m_ext_id] = 1;
         }

         fill_basic_flow(flow, tmplt_ptr, record_ptr);
         ext->fill_unirec(tmplt_ptr, record_ptr); /* Add each extension header into unirec record. */
      }
      ext = ext->m_next;
   }
   //send the last record with all plugin data
   for (size_t ifc_num = 0; ifc_num < m_ifc_cnt && !(m_basic_idx >= 0) && ext_processed_cnd > 0; ifc_num++) {
      tmplt_ptr = m_tmplts[ifc_num];
      record_ptr = m_records[ifc_num];
      trap_send(ifc_num, record_ptr, ur_rec_size(tmplt_ptr, record_ptr));
   }
   return 0;
}

/**
 * \brief Fill record with basic flow fields.
 * \param [in] flow Flow record.
 * \param [in] tmplt_ptr Pointer to unirec template.
 * \param [out] record_ptr Pointer to unirec record.
 */
void UnirecExporter::fill_basic_flow(const Flow &flow, ur_template_t *tmplt_ptr, void *record_ptr)
{
   ur_time_t tmp_time;

   if (flow.ip_version == IP::v4) {
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

   if (m_odid) {
      ur_set(tmplt_ptr, record_ptr, F_ODID, m_link_bit_field);
   } else {
      ur_set(tmplt_ptr, record_ptr, F_LINK_BIT_FIELD, m_link_bit_field);
   }
   ur_set(tmplt_ptr, record_ptr, F_DIR_BIT_FIELD, m_dir_bit_field);
   ur_set(tmplt_ptr, record_ptr, F_PROTOCOL, flow.ip_proto);
   ur_set(tmplt_ptr, record_ptr, F_SRC_PORT, flow.src_port);
   ur_set(tmplt_ptr, record_ptr, F_DST_PORT, flow.dst_port);
   ur_set(tmplt_ptr, record_ptr, F_PACKETS, flow.src_packets);
   ur_set(tmplt_ptr, record_ptr, F_BYTES, flow.src_bytes);
   ur_set(tmplt_ptr, record_ptr, F_TCP_FLAGS, flow.src_tcp_flags);
   ur_set(tmplt_ptr, record_ptr, F_PACKETS_REV, flow.dst_packets);
   ur_set(tmplt_ptr, record_ptr, F_BYTES_REV, flow.dst_bytes);
   ur_set(tmplt_ptr, record_ptr, F_TCP_FLAGS_REV, flow.dst_tcp_flags);

   ur_set(tmplt_ptr, record_ptr, F_DST_MAC, mac_from_bytes(const_cast<uint8_t*>(flow.dst_mac)));
   ur_set(tmplt_ptr, record_ptr, F_SRC_MAC, mac_from_bytes(const_cast<uint8_t*>(flow.src_mac)));
}

}
#endif
