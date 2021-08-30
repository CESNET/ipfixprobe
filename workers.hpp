/**
 * \file workers.hpp
 * \brief Exporter worker procedures
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

#ifndef IPXP_WORKERS_HPP
#define IPXP_WORKERS_HPP

#include <future>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/output.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ring.h>

namespace ipxp {

#define MICRO_SEC 1000000L

struct InputStats {
   uint64_t packets;
   uint64_t parsed;
   uint64_t bytes;
   uint64_t qtime;
   bool error;
   std::string msg;
};

struct StorageStats {
   bool error;
   std::string msg;
};

struct OutputStats {
   uint64_t biflows;
   uint64_t bytes;
   uint64_t packets;
   uint64_t dropped;
   bool error;
   std::string msg;
};

struct WorkPipeline {
   struct {
      InputPlugin *plugin;
      std::thread *thread;
      std::promise<InputStats> *promise;
   } input;
   struct {
      StoragePlugin *plugin;
      std::thread *thread;
      std::promise<StorageStats> *promise;
      std::vector<ProcessPlugin *> plugins;
   } storage;
   ipx_ring_t *queue;
};

struct OutputWorker {
   OutputPlugin *plugin;
   std::thread *thread;
   std::promise<OutputStats> *promise;
   ipx_ring_t *queue;
};

void input_thread(InputPlugin *plugin, PacketBlock *pkts, size_t block_cnt, uint64_t pkt_limit, ipx_ring_t *queue,
      std::promise<InputStats> *threadOutput);
void storage_thread(StoragePlugin *cache, ipx_ring_t *queue, std::promise<StorageStats> *threadOutput);
void output_thread(OutputPlugin *exp, ipx_ring_t *queue, std::promise<OutputStats> *threadOutput, uint32_t fps);

}

#endif /* IPXP_WORKERS_HPP */
