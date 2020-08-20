/**
 * \file stats.cpp
 * \brief Plugin periodically printing statistics about flow cache
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
#include "stats.h"

#include <iostream>
#include <iomanip>
#include <sys/time.h>

using namespace std;

// Constructor
StatsPlugin::StatsPlugin(struct timeval interval, ostream &out)
 : interval(interval), out(out)
{
}

void StatsPlugin::init()
{
   packets = 0;
   new_flows = 0;
   cache_hits = 0;
   flows_in_cache = 0;
   init_ts = true;
   print_header();
}

int StatsPlugin::post_create(Flow &rec, const Packet &pkt)
{
   packets += 1;
   new_flows += 1;
   flows_in_cache += 1;
   check_timestamp(pkt);
   return 0;
}

int StatsPlugin::post_update(Flow &rec, const Packet &pkt)
{
   packets += 1;
   cache_hits += 1;
   check_timestamp(pkt);
   return 0;
}

void StatsPlugin::pre_export(Flow &rec)
{
   flows_in_cache -= 1;
}

void StatsPlugin::finish()
{
   print_stats(last_ts);
}

void StatsPlugin::check_timestamp(const Packet &pkt)
{
   if (init_ts) {
      init_ts = false;
      last_ts = pkt.timestamp;
      return;
   }

   struct timeval tmp;
   timeradd(&last_ts, &interval, &tmp);

   if (timercmp(&pkt.timestamp, &tmp, >)) {
      print_stats(last_ts);
      timeradd(&last_ts, &interval, &last_ts);
      packets = 0;
      new_flows = 0;
      cache_hits = 0;
   }
}

void StatsPlugin::print_header() const
{
   out << "#timestamp packets hits newflows incache" << endl;
}

void StatsPlugin::print_stats(const struct timeval &ts) const
{
   out << ts.tv_sec << "." << ts.tv_usec << " ";
   out << packets << " " << cache_hits << " " << new_flows << " " << flows_in_cache << endl;
}
