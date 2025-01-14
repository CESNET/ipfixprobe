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
 *
 *
 */

#ifndef IPXP_OUTPUT_HPP
#define IPXP_OUTPUT_HPP

#include "plugin.hpp"
#include "process.hpp"
#include "flowifc.hpp"

#include <telemetry.hpp>
#include <atomic>
#include <cstdint>

namespace ipxp {

#define DEFAULT_EXPORTER_ID 1

struct OutputPluginStats {
   uint64_t flows_seen = 0;
   uint64_t flows_dropped = 0;
   uint64_t flows_exported = 0;
   uint64_t bytes_exported = 0;

   void clear()
   {
      flows_seen = 0;
      flows_dropped = 0;
      flows_exported = 0;
      bytes_exported = 0;
   }
};

struct OutputPluginAtomicStats {
   std::atomic<uint64_t> flows_seen = 0;
   std::atomic<uint64_t> flows_dropped = 0;
   std::atomic<uint64_t> flows_exported = 0;
   std::atomic<uint64_t> bytes_exported = 0;
   std::atomic<uint64_t> fps_exported = 0;
   std::atomic<uint64_t> mbps_exported = 0;


   void updatePktBurstStats(const OutputPluginStats& basicStats, uint64_t timestamp)
   {
      flows_seen.fetch_add(basicStats.flows_seen, std::memory_order_relaxed);
      flows_dropped.fetch_add(basicStats.flows_dropped, std::memory_order_relaxed);
      flows_exported.fetch_add(basicStats.flows_exported, std::memory_order_relaxed);
      bytes_exported.fetch_add(basicStats.bytes_exported, std::memory_order_relaxed);

      if (timestamp == 0) {
         fps_exported.store(0);
         mbps_exported.store(0);
         return;
      }

      fps_exported.store(basicStats.flows_exported * 1000000000 / timestamp);
      mbps_exported.store(basicStats.bytes_exported * 8 * 1000000000 / timestamp / 1024 / 1024);
   }
};

static telemetry::Dict createOutputPluginStatsDict(const OutputPluginAtomicStats& burstStats)
{
	telemetry::Dict dict;
   dict["flows_seen"] = burstStats.flows_seen;
   dict["flows_dropped"] = burstStats.flows_dropped;
   dict["flows_exported"] = burstStats.flows_exported;
   dict["bytes_exported"] = burstStats.bytes_exported;
   dict["fps_exported"] = burstStats.fps_exported;
   dict["mbps_exported"] = burstStats.mbps_exported;
	return dict;
}

/**
 * \brief Base class for flow exporters.
 */
class OutputPlugin : public Plugin
{
public:
   typedef std::vector<std::pair<std::string, ProcessPlugin *>> Plugins;

   OutputPlugin() = default;

   virtual ~OutputPlugin() {}

   void init(const char *params, Plugins &plugins, const std::shared_ptr<telemetry::Directory>& dir)
   {
      const auto statsFile = dir->addFile(
		"basic_stats",
		{.read = [this]() { return createOutputPluginStatsDict(m_atomicStats); },
		 .clear = nullptr});

      m_holder.add(statsFile);

      init_plugin(params, plugins, dir);
   }

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

   void update_stats(uint64_t timestamp) override final
   {
      m_atomicStats.updatePktBurstStats(m_stats, timestamp);
      m_stats.clear();

      update_plugin_stats(timestamp);
   }

   const OutputPluginAtomicStats& get_stats() const
   {
      return m_atomicStats;
   }


protected:
   virtual void init_plugin(const char *params, Plugins &plugins, const std::shared_ptr<telemetry::Directory>& dir) = 0;


   virtual void update_plugin_stats(uint64_t timestamp)
   {
      (void) timestamp;
   }

   OutputPluginStats m_stats = {};
   telemetry::Holder m_holder;
private:
   OutputPluginAtomicStats m_atomicStats = {};
};

}
#endif /* IPXP_OUTPUT_HPP */
