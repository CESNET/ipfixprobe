/**
 * \file workers.cpp
 * \brief Exporter worker procedures source
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

#include <unistd.h>
#include <sys/time.h>

#include "workers.hpp"
#include "ipfixprobe.hpp"

namespace ipxp {

#define MICRO_SEC 1000000L

void input_storage_worker(InputPlugin *plugin, StoragePlugin *cache, size_t queue_size, uint64_t pkt_limit,
                  std::promise<WorkerResult> *out, std::atomic<InputStats> *out_stats)
{
   struct timespec start_cache;
   struct timespec end_cache;
   struct timespec begin = {0, 0};
   struct timespec end = {0, 0};
   struct timeval ts = {0, 0};
   bool timeout = false;
   InputPlugin::Result ret;
   InputStats stats = {0, 0, 0, 0, 0};
   WorkerResult res = {false, ""};

   PacketBlock block(queue_size);

#ifdef __linux__
   const clockid_t clk_id = CLOCK_MONOTONIC_COARSE;
#else
   const clockid_t clk_id = CLOCK_MONOTONIC;
#endif

   while (!terminate_input) {
      block.cnt = 0;
      block.bytes = 0;

      if (pkt_limit && plugin->m_parsed + block.size >= pkt_limit) {
         if (plugin->m_parsed >= pkt_limit) {
            break;
         }
         block.size = pkt_limit - plugin->m_parsed;
      }
      try {
         ret = plugin->get(block);
      } catch (PluginError &e) {
         res.error = true;
         res.msg = e.what();
         break;
      }
      if (ret == InputPlugin::Result::TIMEOUT) {
         clock_gettime(clk_id, &end);
         if (!timeout) {
            timeout = true;
            begin = end;
         }
         struct timespec diff = {end.tv_sec - begin.tv_sec, end.tv_nsec - begin.tv_nsec};
         if (diff.tv_nsec < 0) {
            diff.tv_nsec += 1000000000;
            diff.tv_sec--;
         }
         cache->export_expired(ts.tv_sec + diff.tv_sec);
         usleep(1);
         continue;
      } else if (ret == InputPlugin::Result::PARSED) {
         stats.packets = plugin->m_seen;
         stats.parsed = plugin->m_parsed;
         stats.dropped = plugin->m_dropped;
         stats.bytes += block.bytes;
         clock_gettime(clk_id, &start_cache);
         try {
            for (unsigned i = 0; i < block.cnt; i++) {
               cache->put_pkt(block.pkts[i]);
            }
            ts = block.pkts[block.cnt - 1].ts;
         } catch (PluginError &e) {
            res.error = true;
            res.msg = e.what();
            break;
         }
         timeout = false;
         clock_gettime(clk_id, &end_cache);

         int64_t time = end_cache.tv_nsec - start_cache.tv_nsec;
         if (start_cache.tv_sec != end_cache.tv_sec) {
            time += 1000000000;
         }
         stats.qtime += time;

         out_stats->store(stats);
      } else if (ret == InputPlugin::Result::ERROR) {
         res.error = true;
         res.msg = "error occured during reading";
         break;
      } else if (ret == InputPlugin::Result::END_OF_FILE) {
         break;
      }
   }

   stats.packets = plugin->m_seen;
   stats.parsed = plugin->m_parsed;
   stats.dropped = plugin->m_dropped;
   out_stats->store(stats);
   cache->finish();
   auto outq = cache->get_queue();
   while (ipx_ring_cnt(outq)) {
      usleep(1);
   }
   out->set_value(res);
}

static long timeval_diff(const struct timeval *start, const struct timeval *end)
{
   return (end->tv_sec - start->tv_sec) * MICRO_SEC
          + (end->tv_usec - start->tv_usec);
}

void output_worker(OutputPlugin *exp, ipx_ring_t *queue, std::promise<WorkerResult> *out, std::atomic<OutputStats> *out_stats,
   uint32_t fps)
{
   WorkerResult res = {false, ""};
   OutputStats stats = {0, 0, 0, 0};
   struct timespec sleep_time = {0};
   struct timeval begin;
   struct timeval end;
   struct timeval last_flush;
   uint32_t pkts_from_begin = 0;
   double time_per_pkt = 0;

   if (fps != 0) {
      time_per_pkt = 1000000.0 / fps; // [micro seconds]
   }

   // Rate limiting algorithm from https://github.com/CESNET/ipfixcol2/blob/master/src/tools/ipfixsend/sender.c#L98
   gettimeofday(&begin, nullptr);
   last_flush = begin;
   while (1) {
      gettimeofday(&end, nullptr);

      Flow *flow = static_cast<Flow *>(ipx_ring_pop(queue));
      if (!flow) {
         if (end.tv_sec - last_flush.tv_sec > 1) {
            last_flush = end;
            exp->flush();
         }
         if (terminate_export && !ipx_ring_cnt(queue)) {
            break;
         }
         continue;
      }

      stats.biflows++;
      stats.bytes += flow->src_bytes + flow->dst_bytes;
      stats.packets += flow->src_packets + flow->dst_packets;
      stats.dropped = exp->m_flows_dropped;
      out_stats->store(stats);
      try {
         exp->export_flow(*flow);
      } catch (PluginError &e) {
         res.error = true;
         res.msg = e.what();
         break;
      }

      pkts_from_begin++;
      if (fps == 0) {
         // Limit for packets/s is not enabled
         continue;
      }

      // Calculate expected time of sending next packet
      long elapsed = timeval_diff(&begin, &end);
      if (elapsed < 0) {
         // Should be never negative. Just for sure...
         elapsed = pkts_from_begin * time_per_pkt;
      }

      long next_start = pkts_from_begin * time_per_pkt;
      long diff = next_start - elapsed;

      if (diff >= MICRO_SEC) {
         diff = MICRO_SEC - 1;
      }

      // Sleep
      if (diff > 0) {
         sleep_time.tv_nsec = diff * 1000L;
         nanosleep(&sleep_time, nullptr);
      }

      if (pkts_from_begin >= fps) {
         // Restart counter
         gettimeofday(&begin, nullptr);
         pkts_from_begin = 0;
      }
   }

   exp->flush();
   stats.dropped = exp->m_flows_dropped;
   out_stats->store(stats);
   out->set_value(res);
}

}
