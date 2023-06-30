/**
 * \file flowifc.hpp
 * \brief Structs/classes for communication between flow cache and exporter
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

#ifndef IPXP_FLOWIFC_HPP
#define IPXP_FLOWIFC_HPP

/* Interface between flow cache and flow exporter. */

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#include "fields.h"
#else
#define UR_FIELDS(...)
#endif

#include <arpa/inet.h>
#include "ipaddr.hpp"
#include <string>

namespace ipxp {

#define BASIC_PLUGIN_NAME "basic"

int register_extension();
int get_extension_cnt();

/**
 * \brief Flow record extension base struct.
 */
struct RecordExt {
   RecordExt *m_next; /**< Pointer to next extension */
   int m_ext_id; /**< Identifier of extension. */

   /**
    * \brief Constructor.
    * \param [in] id ID of extension.
    */
   RecordExt(int id) : m_next(nullptr), m_ext_id(id)
   {
   }

#ifdef WITH_NEMEA
   /**
    * \brief Fill unirec record with stored extension data.
    * \param [in] tmplt Unirec template.
    * \param [out] record Pointer to the unirec record.
    */
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
   }

   /**
    * \brief Get unirec template string.
    * \return Unirec template string.
    */
   virtual const char *get_unirec_tmplt() const
   {
      return "";
   }
#endif

   /**
    * \brief Fill IPFIX record with stored extension data.
    * \param [out] buffer IPFIX template record buffer.
    * \param [in] size IPFIX template record buffer size.
    * \return Number of bytes written to buffer or -1 if data cannot be written.
    */
   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      return 0;
   }

   /**
    * \brief Get ipfix string fields.
    * \return Return ipfix fields array.
    */
   virtual const char **get_ipfix_tmplt() const
   {
      return nullptr;
   }

   /**
    * \brief Get text representation of exported elements
    * \return Return fields converted to text
    */
   virtual std::string get_text() const
   {
      return "";
   }

   /**
    * \brief Add extension at the end of linked list.
    * \param [in] ext Extension to add.
    */
   void add_extension(RecordExt *ext)
   {
      RecordExt **tmp = &m_next;
      while (*tmp) {
         tmp = &(*tmp)->m_next;
      }
      *tmp = ext;
   }

   /**
    * \brief Virtual destructor.
    */
   virtual ~RecordExt()
   {
      if (m_next != nullptr) {
         delete m_next;
      }
   }
};

struct Record {
   RecordExt *m_exts; /**< Extension headers. */

   /**
    * \brief Add new extension header.
    * \param [in] ext Pointer to the extension header.
    */
   void add_extension(RecordExt* ext)
   {
      if (m_exts == nullptr) {
         m_exts = ext;
      } else {
         RecordExt *ext_ptr = m_exts;
         while (ext_ptr->m_next != nullptr) {
            ext_ptr = ext_ptr->m_next;
         }
         ext_ptr->m_next = ext;
      }
   }

   /**
    * \brief Get given extension.
    * \param [in] id Type of extension.
    * \return Pointer to the requested extension or nullptr if extension is not present.
    */
   RecordExt *get_extension(int id) const
   {
      RecordExt *ext = m_exts;
      while (ext != nullptr) {
         if (ext->m_ext_id == id) {
            return ext;
         }
         ext = ext->m_next;
      }
      return nullptr;
   }
    /**
     * \brief Remove given extension.
     * \param [in] id Type of extension.
     * \return True when successfully removed
     */
    bool remove_extension(int id)
    {
       RecordExt *ext      = m_exts;
       RecordExt *prev_ext = nullptr;

       while (ext != nullptr) {
          if (ext->m_ext_id == id) {
             if (prev_ext == nullptr) { // at beginning
                m_exts = ext->m_next;
             } else if (ext->m_next == nullptr) { // at end
                prev_ext->m_next = nullptr;
             } else { // in middle
                prev_ext->m_next = ext->m_next;
             }
             ext->m_next = nullptr;
             delete ext;
             return true;
          }
          prev_ext = ext;
          ext      = ext->m_next;
       }
       return false;
    }

   /**
    * \brief Remove extension headers.
    */
   void remove_extensions()
   {
      if (m_exts != nullptr) {
         delete m_exts;
         m_exts = nullptr;
      }
   }

   /**
    * \brief Constructor.
    */
   Record() : m_exts(nullptr)
   {
   }

   /**
    * \brief Destructor.
    */
   virtual ~Record()
   {
      remove_extensions();
   }
};

#define FLOW_END_INACTIVE 0x01
#define FLOW_END_ACTIVE   0x02
#define FLOW_END_EOF      0x03
#define FLOW_END_FORCED   0x04
#define FLOW_END_NO_RES   0x05

/**
 * \brief Flow record struct constaining basic flow record data and extension headers.
 */
struct Flow : public Record {
   struct timeval time_first;
   struct timeval time_last;
   uint64_t src_bytes;
   uint64_t dst_bytes;
   uint32_t src_packets;
   uint32_t dst_packets;
   uint8_t  src_tcp_flags;
   uint8_t  dst_tcp_flags;

   uint8_t  ip_version;

   uint8_t  ip_proto;
   uint16_t src_port;
   uint16_t dst_port;
   ipaddr_t src_ip;
   ipaddr_t dst_ip;

   uint8_t src_mac[6];
   uint8_t dst_mac[6];
   uint8_t end_reason;
};

}
#endif /* IPXP_FLOWIFC_HPP */
