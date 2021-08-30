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

namespace ipxp {

struct template_t;

#define BASIC_PLUGIN_NAME "basic"

/**
 * \brief Extension header type enum.
 */
enum extTypeEnum {
   http = 0,
   rtsp,
   tls,
   dns,
   sip,
   ntp,
   smtp,
   passivedns,
   pstats,
   idpcontent,
   ovpn,
   ssdp,
   dnssd,
   netbios,
   basicplus,
   bstats,
   phists,
   wg,
   /* Add extension header identifiers for your plugins here */
   EXTENSION_CNT
};

/**
 * \brief Flow record extension base struct.
 */
struct RecordExt {
   RecordExt *next; /**< Pointer to next extension */
   extTypeEnum extType; /**< Type of extension. */

   /**
    * \brief Constructor.
    * \param [in] type Type of extension.
    */
   RecordExt(extTypeEnum type) : next(nullptr), extType(type)
   {
   }

#ifdef WITH_NEMEA
   /**
    * \brief Fill unirec record with stored extension data.
    * \param [in] tmplt Unirec template.
    * \param [out] record Pointer to the unirec record.
    */
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
   }
#endif

   /**
    * \brief Add extension at the end of linked list.
    * \param [in] ext Extension to add.
    */
   void addExtension(RecordExt *ext)
   {
      if (next == nullptr) {
         next = ext;
      } else {
         RecordExt *tmp = next;
         while (tmp->next != nullptr) {
            tmp = tmp->next;
         }
         tmp->next = ext;
      }
   }

   /**
    * \brief Fill IPFIX record with stored extension data.
    * \param [out] buffer IPFIX template record buffer.
    * \param [in] size IPFIX template record buffer size.
    * \return Number of bytes written to buffer or -1 if data cannot be written.
    */
   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      return 0;
   }

   /**
    * \brief Virtual destructor.
    */
   virtual ~RecordExt()
   {
      if (next != nullptr) {
         delete next;
      }
   }
};

struct Record {
   RecordExt *exts; /**< Extension headers. */

   /**
    * \brief Add new extension header.
    * \param [in] ext Pointer to the extension header.
    */
   void addExtension(RecordExt* ext)
   {
      if (exts == nullptr) {
         exts = ext;
      } else {
         RecordExt *ext_ptr = exts;
         while (ext_ptr->next != nullptr) {
            ext_ptr = ext_ptr->next;
         }
         ext_ptr->next = ext;
      }
   }

   /**
    * \brief Get given extension.
    * \param [in] extType Type of extension.
    * \return Pointer to the requested extension or nullptr if extension is not present.
    */
   RecordExt *getExtension(extTypeEnum extType)
   {
      RecordExt *ext_ptr = exts;
      while (ext_ptr != nullptr) {
         if (ext_ptr->extType == extType) {
            return ext_ptr;
         }
         ext_ptr = ext_ptr->next;
      }
      return nullptr;
   }

   /**
    * \brief Remove extension headers.
    */
   void removeExtensions()
   {
      if (exts != nullptr) {
         delete exts;
         exts = nullptr;
      }
   }

   /**
    * \brief Constructor.
    */
   Record() : exts(nullptr)
   {
   }

   /**
    * \brief Destructor.
    */
   virtual ~Record()
   {
      removeExtensions();
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
   uint64_t src_octet_total_length;
   uint64_t dst_octet_total_length;
   uint32_t src_pkt_total_cnt;
   uint32_t dst_pkt_total_cnt;
   uint8_t  src_tcp_control_bits;
   uint8_t  dst_tcp_control_bits;

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
