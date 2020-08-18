/**
 * \file unirecexporter.h
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

#ifndef UNIREC_EXPORTER_H
#define UNIREC_EXPORTER_H

#include <string>
#include <vector>
#include <map>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "flowcacheplugin.h"
#include "flowexporter.h"
#include "packet.h"

using namespace std;

/**
 * \brief Class for exporting flow records.
 */
class UnirecExporter : public FlowExporter
{
public:
   UnirecExporter(bool send_eof);
   int init(const vector<FlowCachePlugin *> &plugins, int ifc_cnt, int basic_ifc_num, uint64_t link, uint8_t dir, bool odid);
   void close();
   int export_flow(Flow &flow);
   int export_packet(Packet &pkt);

private:
   void fill_basic_flow(Flow &flow, ur_template_t *tmplt_ptr, void *record_ptr);
   void fill_packet_fields(Packet &pkt, ur_template_t *tmplt_ptr, void *record_ptr);
   void free_unirec_resources();

   int out_ifc_cnt;           /**< Number of output interfaces. */
   int basic_ifc_num;         /**< Basic output interface number. */
   int *ifc_mapping;          /**< Contain extension id (as index) -> output interface number mapping. */
   ur_template_t **tmplt;     /**< Pointer to unirec templates. */
   void **record;             /**< Pointer to unirec records. */
   bool eof;                  /**< Send eof when module exits. */
   bool send_odid;            /**< Export ODID field instead of LINK_BIT_FIELD. */

   uint64_t link_bit_field;   /**< Link bit field value. */
   uint8_t dir_bit_field;     /**< Direction bit field value. */
};

#endif
