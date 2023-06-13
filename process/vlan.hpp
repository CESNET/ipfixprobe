/**
 * \file vlan.hpp
 * \brief Plugin for parsing vlan traffic.
 * \author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
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

#ifndef IPXP_PROCESS_VLAN_HPP
#define IPXP_PROCESS_VLAN_HPP

#include <cstring>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

#include <cstdint>
#include <string>
#include <sstream>

namespace ipxp {

#define VLAN_UNIREC_TEMPLATE "VLAN_ID"

UR_FIELDS (
   uint16 VLAN_ID
)

/**
 * \brief Flow record extension header for storing parsed VLAN data.
 */
struct RecordExtVLAN : public RecordExt {
   static int REGISTERED_ID;

   // vlan id is in the host byte order
   uint16_t vlan_id;

   RecordExtVLAN() : RecordExt(REGISTERED_ID), vlan_id(0)
   {
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_VLAN_ID, vlan_id);
   }

   const char *get_unirec_tmplt() const
   {
      return VLAN_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      const int LEN = sizeof(vlan_id);

      if (size < LEN) {
         return -1;
      }

      *reinterpret_cast<uint16_t *>(buffer) = htons(vlan_id);
      return 0;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_VLAN_TEMPLATE(IPFIX_FIELD_NAMES)
         NULL
      };
      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "vlan_id=\"" << vlan_id << '"';
      return out.str();
   }
};

/**
 * \brief Process plugin for parsing VLAN packets.
 */
class VLANPlugin : public ProcessPlugin
{
public:
   OptionsParser *get_parser() const { return new OptionsParser("vlan", "Parse VLAN traffic"); }
   std::string get_name() const { return "vlan"; }
   RecordExt *get_ext() const { return new RecordExtVLAN(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
};

}
#endif /* IPXP_PROCESS_VLAN_HPP */

