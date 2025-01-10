/**
 * \file input.hpp
 * \brief Generic interface of input plugin
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

#ifndef IPXP_INPUT_HPP
#define IPXP_INPUT_HPP

#include <string>
#include <memory>
#include <telemetry.hpp>

#include "telemetry-utils.hpp"
#include "plugin.hpp"
#include "packet.hpp"
#include "parser-stats.hpp"

namespace ipxp {

/**
 * \brief Base class for packet receivers.
 */
class InputPlugin : public TelemetryUtils, public Plugin
{
public:
   enum class Result {
      TIMEOUT = 0,
      PARSED,
      NOT_PARSED,
      END_OF_FILE,
      ERROR
   };

   uint64_t m_seen;
   uint64_t m_parsed;
   uint64_t m_dropped;

   InputPlugin();
   virtual ~InputPlugin() {}

   virtual Result get(PacketBlock &packets) = 0;

   void set_telemetry_dirs(
      std::shared_ptr<telemetry::Directory> plugin_dir, 
      std::shared_ptr<telemetry::Directory> queues_dir);

#ifdef WITH_CTT
   virtual std::pair<std::string, unsigned> get_ctt_config() const {
      throw PluginError("CTT is not supported by this input plugin");
   }
#endif /* WITH_CTT */

protected:
   virtual void configure_telemetry_dirs(
      std::shared_ptr<telemetry::Directory> plugin_dir, 
      std::shared_ptr<telemetry::Directory> queues_dir) {};

   ParserStats m_parser_stats;

private:
   void create_parser_stats_telemetry(std::shared_ptr<telemetry::Directory> queues_dir);
};

}
#endif /* IPXP_INPUT_TEMPLATE_HPP */
