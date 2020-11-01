/**
 * \file idpcontentplugin.h
 * \brief Plugin for parsing idpcontent traffic.
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
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

#ifndef IDPCONTENTPLUGIN_H
#define IDPCONTENTPLUGIN_H

#include <string>
#include <cstring>

#ifdef WITH_NEMEA
# include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

#define IDPCONTENT_SIZE       100
#define EXPORTED_PACKETS      2
#define IDP_CONTENT_INDEX     0
#define IDP_CONTENT_REV_INDEX 1

using namespace std;

/**
 * \brief Flow record extension header for storing parsed IDPCONTENT packets.
 */

struct idpcontentArray {
   idpcontentArray() : size(0){ };
   uint8_t size;
   uint8_t data[IDPCONTENT_SIZE];
};

struct RecordExtIDPCONTENT : RecordExt {
   uint8_t         pkt_export_flg[EXPORTED_PACKETS];
   idpcontentArray idps[EXPORTED_PACKETS];


   RecordExtIDPCONTENT() : RecordExt(idpcontent)
   { }

   #ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set_var(tmplt, record, F_IDP_CONTENT, idps[IDP_CONTENT_INDEX].data, idps[IDP_CONTENT_INDEX].size);
      ur_set_var(tmplt, record, F_IDP_CONTENT_REV, idps[IDP_CONTENT_REV_INDEX].data, idps[IDP_CONTENT_REV_INDEX].size);
   }

   #endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      uint32_t pos = 0;

      if (idps[IDP_CONTENT_INDEX].size + idps[IDP_CONTENT_REV_INDEX].size + 2 > size) {
         return -1;
      }
      for (int i = 0; i < EXPORTED_PACKETS; i++) {
         buffer[pos++] = idps[i].size;
         memcpy(buffer + pos, idps[i].data, idps[i].size);
         pos += idps[i].size;
      }

      return pos;
   }
};

/**
 * \brief Flow cache plugin for parsing IDPCONTENT packets.
 */
class IDPCONTENTPlugin : public FlowCachePlugin
{
public:
   IDPCONTENTPlugin(const options_t &module_options);
   IDPCONTENTPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   const char **get_ipfix_string();
   string get_unirec_field_string();
   void update_record(RecordExtIDPCONTENT *pstats_data, const Packet &pkt);

private:
   bool print_stats; /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif // ifndef IDPCONTENTPLUGIN_H
