/**
 * \file stats.cpp
 * \brief Plugin periodically printing statistics about flow cache
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
#include "stats.hpp"

#include <iostream>
#include <iomanip>
#include <sys/time.h>

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("stats", [](){return new StatsPlugin();});
   register_plugin(&rec);
}

StatsPlugin::StatsPlugin() :
   m_packets(0), m_new_flows(0), m_cache_hits(0), m_flows_in_cache(0), m_init_ts(true),
   m_interval({STATS_PRINT_INTERVAL, 0}), m_last_ts({0}), m_out(&std::cout)
{
}

StatsPlugin::~StatsPlugin()
{
   close();
}

void StatsPlugin::init(const char *params)
{
   StatsOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   m_interval = {parser.m_interval, 0};
   if (parser.m_out == "stdout") {
      m_out = &std::cout;
   } else if (parser.m_out == "stderr") {
      m_out = &std::cerr;
   } else {
      throw PluginError("Unknown argument " + parser.m_out);
   }
   print_header();
}

void StatsPlugin::close()
{
}

ProcessPlugin *StatsPlugin::copy()
{
   return new StatsPlugin(*this);
}

int StatsPlugin::post_create(Flow &rec, const Packet &pkt)
{
   m_packets += 1;
   m_new_flows += 1;
   m_flows_in_cache += 1;
   check_timestamp(pkt);
   return 0;
}

int StatsPlugin::post_update(Flow &rec, const Packet &pkt)
{
   m_packets += 1;
   m_cache_hits += 1;
   check_timestamp(pkt);
   return 0;
}

void StatsPlugin::pre_export(Flow &rec)
{
   m_flows_in_cache -= 1;
}

void StatsPlugin::finish(bool print_stats)
{
   print_line(m_last_ts);
}

void StatsPlugin::check_timestamp(const Packet &pkt)
{
   if (m_init_ts) {
      m_init_ts = false;
      m_last_ts = pkt.ts;
      return;
   }

   struct timeval tmp;
   timeradd(&m_last_ts, &m_interval, &tmp);

   if (timercmp(&pkt.ts, &tmp, >)) {
      print_line(m_last_ts);
      timeradd(&m_last_ts, &m_interval, &m_last_ts);
      m_packets = 0;
      m_new_flows = 0;
      m_cache_hits = 0;
   }
}

void StatsPlugin::print_header() const
{
   *m_out << "#timestamp packets hits newflows incache" << std::endl;
}

void StatsPlugin::print_line(const struct timeval &ts) const
{
   *m_out << ts.tv_sec << "." << ts.tv_usec << " ";
   *m_out << m_packets << " " << m_cache_hits << " " << m_new_flows << " " << m_flows_in_cache << std::endl;
}

}
