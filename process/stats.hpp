/**
 * \file stats.hpp
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
#ifndef IPXP_PROCESS_STATS_HPP
#define IPXP_PROCESS_STATS_HPP

#include <ostream>

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

#define STATS_PRINT_INTERVAL 1

class StatsOptParser : public OptionsParser
{
public:
   uint32_t m_interval;
   std::string m_out;

   StatsOptParser() : OptionsParser("stats", "Print storage plugin statistics"), m_interval(STATS_PRINT_INTERVAL), m_out("stdout")
   {
      register_option("i", "interval", "SECS", "Print interval in seconds",
         [this](const char *arg){try {m_interval = str2num<decltype(m_interval)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("o", "out", "DESC", "Print statistics to stdout or stderr",
         [this](const char *arg){m_out = arg ; return m_out != "stdout" && m_out != "stderr";}, OptionFlags::RequiredArgument);
   }
};

class StatsPlugin : public ProcessPlugin
{
public:
   StatsPlugin();
   ~StatsPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new StatsOptParser(); }
   std::string get_name() const { return "stats"; }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish(bool print_stats);

private:
   uint64_t m_packets;
   uint64_t m_new_flows;
   uint64_t m_cache_hits;
   uint64_t m_flows_in_cache;

   bool m_init_ts;
   struct timeval m_interval;
   struct timeval m_last_ts;
   std::ostream *m_out;

   void check_timestamp(const Packet &pkt);
   void print_header() const;
   void print_line(const struct timeval &ts) const;
};

}
#endif /* IPXP_PROCESS_STATS_HPP */
