/**
 * \file scitags.hpp
 * \brief Plugin for parsing scitags traffic.
 * \author Karel Hynek <karel.hynek@cesnet.cz>
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
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

#ifndef IPXP_PROCESS_SCITAGS_HPP
#define IPXP_PROCESS_SCITAGS_HPP

#include <cstring>
#include <sstream>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define SCITAGS_UNIREC_TEMPLATE "SCITAG_EXPERIMENT_ID,SCITAG_EXPERIMENT_ACTIVITY" /* TODO: unirec template */

UR_FIELDS (
   uint16 SCITAG_EXPERIMENT_ID,
   uint8  SCITAG_EXPERIMENT_ACTIVITY
)

/**
 * \brief Flow record extension header for storing parsed SCITAGS data.
 */
struct RecordExtSCITAGS : public RecordExt {
   static int REGISTERED_ID;

   uint16_t experiment_id;
   uint8_t  experiment_activity;
   uint32_t flow_label;
   bool     flow_label_set;
   bool     non_constant_flow_label;

   RecordExtSCITAGS() : RecordExt(REGISTERED_ID),
      experiment_id(0),
      experiment_activity(0),
      flow_label(0),
      flow_label_set(false),
      non_constant_flow_label(false)
   {
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_SCITAG_EXPERIMENT_ID, experiment_id);
      ur_set(tmplt, record, F_SCITAG_EXPERIMENT_ACTIVITY, experiment_activity);
   }

   const char *get_unirec_tmplt() const
   {
      return SCITAGS_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      if ((size_t)size < (sizeof(uint16_t) + sizeof(uint8_t))) {
         return -1;
      }
      *(uint16_t*)buffer = htons(experiment_id);
      *(buffer + 2) = experiment_activity;
      return sizeof(uint16_t) + sizeof(uint8_t);
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_SCITAGS_TEMPLATE(IPFIX_FIELD_NAMES)
         NULL
      };
      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "experimentID=" << (uint32_t)experiment_id << ",";
      out << "experimentActivity=" << (uint32_t)experiment_activity << ",";
      return out.str();
   }
};

/**
 * \brief Process plugin for parsing SCITAGS packets.
 */
class SCITAGSPlugin : public ProcessPlugin
{
public:
   SCITAGSPlugin();
   ~SCITAGSPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("scitags", "Parse SCITAGS traffic"); }
   std::string get_name() const { return "scitags"; }
   RecordExt *get_ext() const { return new RecordExtSCITAGS(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void update_record(RecordExtSCITAGS *record, const Packet &pkt);
   static uint32_t bit_reverse(uint32_t value, uint8_t MSB);
   void pre_export(Flow &rec);
};

}
#endif /* IPXP_PROCESS_SCITAGS_HPP */

