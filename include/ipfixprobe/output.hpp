/**
 * \file output.hpp
 * \brief Generic interface of output plugin
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

#ifndef IPXP_OUTPUT_HPP
#define IPXP_OUTPUT_HPP

#include "plugin.hpp"
#include "process.hpp"
#include "flowifc.hpp"

namespace ipxp {

#define DEFAULT_EXPORTER_ID 1

/**
 * \brief Base class for flow exporters.
 */
class OutputPlugin : public Plugin
{
public:
   typedef std::vector<std::pair<std::string, ProcessPlugin *>> Plugins;
   uint64_t m_flows_seen; /**< Number of flows received to export. */
   uint64_t m_flows_dropped; /**< Number of flows that could not be exported. */

   OutputPlugin() : m_flows_seen(0), m_flows_dropped(0) {}
   virtual ~OutputPlugin() {}

   virtual void init(const char *params, Plugins &plugins) = 0;

   enum class Result {
      EXPORTED = 0,
      DROPPED
   };
   /**
    * \brief Send flow record to output interface.
    * \param [in] flow Flow to send.
    * \return 0 on success
    */
   virtual int export_flow(const Flow &flow) = 0;

   /**
    * \brief Force exporter to flush flows to collector.
    */
   virtual void flush()
   {
   }
};

}
#endif /* IPXP_OUTPUT_HPP */
