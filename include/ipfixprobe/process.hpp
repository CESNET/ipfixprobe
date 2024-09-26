/**
 * \file process.hpp
 * \brief Generic interface of processing plugin
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#ifndef IPXP_PROCESS_HPP
#define IPXP_PROCESS_HPP

#include <string>
#include <vector>

#include "plugin.hpp"
#include "packet.hpp"
#include "flowifc.hpp"

namespace ipxp {

/**
 * \brief Tell storage plugin to flush (immediately export) current flow.
 * Behavior when called from post_create, pre_update and post_update: flush current Flow and erase FlowRecord.
 */
#define FLOW_FLUSH                  0x1

/**
 * \brief Tell storage plugin to flush (immediately export) current flow.
 * Behavior when called from post_create: flush current Flow and erase FlowRecord.
 * Behavior when called from pre_update and post_update: flush current Flow, erase FlowRecord and call post_create on packet.
 */
#define FLOW_FLUSH_WITH_REINSERT    0x3

/**
 * \brief Class template for flow cache plugins.
 */
class ProcessPlugin : public Plugin
{
public:
   ProcessPlugin() {}
   virtual ~ProcessPlugin() {}
   virtual ProcessPlugin *copy() = 0;

   virtual RecordExt *get_ext() const
   {
      return nullptr;
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
};

}
#endif /* IPXP_PROCESS_HPP */
