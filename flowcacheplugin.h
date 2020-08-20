/**
 * \file flowcacheplugin.h
 * \brief Generic interface of flow cache plugins (FlowCachePlugin class)
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

#ifndef FLOWCACHEPLUGIN_H
#define FLOWCACHEPLUGIN_H

#include <string>
#include <vector>

#include "packet.h"
#include "flowifc.h"

/**
 * \brief Tell FlowCache to flush (immediately export) current flow.
 * Behavior when called from post_create, pre_update and post_update: flush current Flow and erase FlowRecord.
 */
#define FLOW_FLUSH                  0x1

/**
 * \brief Tell FlowCache to flush (immediately export) current flow.
 * Behavior when called from post_create: flush current Flow and erase FlowRecord.
 * Behavior when called from pre_update and post_update: flush current Flow, erase FlowRecord and call post_create on packet.
 */
#define FLOW_FLUSH_WITH_REINSERT    0x3

/**
 * \biref Tell FlowCache to export currently processed packet.
 * This return value has only effect when called from pre_create method.
 */
#define EXPORT_PACKET               0x4

#define MAX_PAYLOAD_LENGTH MAXPCKTSIZE

using namespace std;

/**
 * \brief Struct containing options for extension headers.
 */
struct plugin_opt {
   string ext_name; /**< Extension name. */
   uint16_t ext_type; /**< Extension type. */
   int out_ifc_num; /**< Output interface number. */
   string params; /**< Parameters for plugin from user. */

   plugin_opt(string extension, uint16_t type, int ifc_num, string params) : ext_name(extension), ext_type(type), out_ifc_num(ifc_num), params(params)
   {
   }
   plugin_opt(string extension, uint16_t type, int ifc_num) : ext_name(extension), ext_type(type), out_ifc_num(ifc_num)
   {
   }
   plugin_opt(string extension, uint16_t type) : ext_name(extension), ext_type(type), out_ifc_num(-1)
   {
   }
};

/**
 * \brief Class template for flow cache plugins.
 */
class FlowCachePlugin
{
public:

   FlowCachePlugin()
   {
   }

   FlowCachePlugin(vector<plugin_opt> options) : options(options)
   {
   }

   /**
    * \brief Virtual destructor.
    */
   virtual ~FlowCachePlugin()
   {
   }

   /**
    * \brief Called before the start of processing.
    */
   virtual void init()
   {
   }

   /**
    * \brief Called before a new flow record is created.
    * \param [in] pkt Parsed packet.
    * \return 0 on success or FLOW_FLUSH option.
    */
   virtual int pre_create(Packet &pkt)
   {
      return 0;
   }

   /**
    * \brief Called after a new flow record is created.
    * \param [in,out] rec Reference to flow record.
    * \param [in] pkt Parsed packet.
    * \return 0 on success or FLOW_FLUSH option.
    */
   virtual int post_create(Flow &rec, const Packet &pkt)
   {
      return 0;
   }

   /**
    * \brief Called before an existing record is update.
    * \param [in,out] rec Reference to flow record.
    * \param [in,out] pkt Parsed packet.
    * \return 0 on success or FLOW_FLUSH option.
    */
   virtual int pre_update(Flow &rec, Packet &pkt)
   {
      return 0;
   }

   /**
    * \brief Called after an existing record is updated.
    * \param [in,out] rec Reference to flow record.
    * \param [in,out] pkt Parsed packet.
    * \return 0 on success or FLOW_FLUSH option.
    */
   virtual int post_update(Flow &rec, const Packet &pkt)
   {
      return 0;
   }

   /**
    * \brief Called before a flow record is exported from the cache.
    * \param [in,out] rec Reference to flow record.
    */
   virtual void pre_export(Flow &rec)
   {
   }

   /**
    * \brief Called when everything is processed.
    */
   virtual void finish()
   {
   }

   /**
    * \brief Get unirec template string from plugin.
    * \return Unirec template string.
    */
   virtual string get_unirec_field_string()
   {
      return "";
   }

   /**
    * \brief Get IPFIX template string from plugin.
    * \return IPFIX template string.
    */
   virtual const char **get_ipfix_string()
   {
      return NULL;
   }

   /**
    * \brief Check if plugin require basic flow fields in unirec template.
    * \return True if basic flow is need to be included, false otherwise.
    */
   virtual bool include_basic_flow_fields()
   {
      return true;
   }

   /**
    * \brief Get plugin options.
    * \return Plugin options.
    */
   vector<plugin_opt> &get_options()
   {
      return options;
   }

   virtual uint32_t max_payload_length()
   {
      return MAX_PAYLOAD_LENGTH;
   }

   vector<plugin_opt> options; /**< Plugin options. */
};

#endif
