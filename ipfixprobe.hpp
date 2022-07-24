/**
 * \file ipfixprobe.hpp
 * \brief Main exporter objects
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

#ifndef IPXP_IPFIXPROBE_HPP
#define IPXP_IPFIXPROBE_HPP

#include <config.h>
#include <string>
#include <thread>
#include <future>
#include <atomic>
#include <csignal>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/output.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/plugin.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>
#include <ipfixprobe/ring.h>
#include "pluginmgr.hpp"
#include "workers.hpp"

namespace ipxp {

extern const uint32_t DEFAULT_IQUEUE_SIZE;
extern const uint32_t DEFAULT_OQUEUE_SIZE;
extern const uint32_t DEFAULT_FPS;

// global termination variable
extern volatile sig_atomic_t terminate_export;
extern volatile sig_atomic_t terminate_input;

class IpfixprobeOptParser;
struct ipxp_conf_t;

void signal_handler(int sig);
void register_handlers();
void error(std::string msg);
void print_help(ipxp_conf_t &conf, const std::string &arg);
void init_packets(ipxp_conf_t &conf);
bool process_plugin_args(ipxp_conf_t &conf, IpfixprobeOptParser &parser);
void main_loop(ipxp_conf_t &conf);
int run(int argc, char *argv[]);

class IpfixprobeOptParser : public OptionsParser {
public:
   std::vector<std::string> m_input;
   std::vector<std::string> m_storage;
   std::vector<std::string> m_output;
   std::vector<std::string> m_process;
   std::string m_pid;
   bool m_daemon;
   uint32_t m_iqueue;
   uint32_t m_oqueue;
   uint32_t m_fps;
   uint32_t m_pkt_bufsize;
   uint32_t m_max_pkts;
   bool m_help;
   std::string m_help_str;
   bool m_version;

   IpfixprobeOptParser() : OptionsParser("ipfixprobe", "flow exporter supporting various custom IPFIX elements"),
                           m_pid(""), m_daemon(false),
                           m_iqueue(DEFAULT_IQUEUE_SIZE), m_oqueue(DEFAULT_OQUEUE_SIZE), m_fps(DEFAULT_FPS),
                           m_pkt_bufsize(1600), m_max_pkts(0), m_help(false), m_help_str(""), m_version(false)
   {
      m_delim = ' ';

      register_option("-i", "--input", "ARGS", "Activate input plugin (-h input for help)",
                      [this](const char *arg) {
                          m_input.push_back(arg);
                          return true;
                      }, OptionFlags::RequiredArgument);
      register_option("-s", "--storage", "ARGS", "Activate storage plugin (-h storage for help)",
                      [this](const char *arg) {
                          m_storage.push_back(arg);
                          return true;
                      }, OptionFlags::RequiredArgument);
      register_option("-o", "--output", "ARGS", "Activate output plugin (-h output for help)",
                      [this](const char *arg) {
                          m_output.push_back(arg);
                          return true;
                      }, OptionFlags::RequiredArgument);
      register_option("-p", "--process", "ARGS", "Activate processing plugin (-h process for help)",
                      [this](const char *arg) {
                          m_process.push_back(arg);
                          return true;
                      }, OptionFlags::RequiredArgument);
      register_option("-q", "--iqueue", "SIZE", "Size of queue between input and storage plugins",
                      [this](const char *arg) {
                          try { m_iqueue = str2num<decltype(m_iqueue)>(arg); } catch (
                                  std::invalid_argument &e) { return false; }
                          return true;
                      }, OptionFlags::RequiredArgument);
      register_option("-Q", "--oqueue", "SIZE", "Size of queue between storage and output plugins",
                      [this](const char *arg) {
                          try { m_oqueue = str2num<decltype(m_oqueue)>(arg); } catch (
                                  std::invalid_argument &e) { return false; }
                          return true;
                      }, OptionFlags::RequiredArgument);
      register_option("-B", "--pbuf", "SIZE", "Size of packet buffer",
                      [this](const char *arg) {
                          try { m_pkt_bufsize = str2num<decltype(m_pkt_bufsize)>(arg); } catch (std::invalid_argument &e) { return false; }
                          return true;
                      },
                      OptionFlags::RequiredArgument);
      register_option("-f", "--fps", "NUM", "Export max flows per second",
                      [this](const char *arg) {
                          try { m_fps = str2num<decltype(m_fps)>(arg); } catch (std::invalid_argument &e) { return false; }
                          return true;
                      },
                      OptionFlags::RequiredArgument);
      register_option("-c", "--count", "SIZE", "Quit after number of packets are processed on each interface",
                      [this](const char *arg) {
                          try { m_max_pkts = str2num<decltype(m_max_pkts)>(arg); } catch (
                                  std::invalid_argument &e) { return false; }
                          return true;
                      }, OptionFlags::RequiredArgument);
      register_option("-P", "--pid", "FILE", "Create pid file", [this](const char *arg) {
          m_pid = arg;
          return m_pid != "";
      }, OptionFlags::RequiredArgument);
      register_option("-d", "--daemon", "", "Run as a standalone process", [this](const char *arg) {
          m_daemon = true;
          return true;
      }, OptionFlags::NoArgument);
      register_option("-h", "--help", "PLUGIN", "Print help text. Supported help for input, storage, output and process plugins", [this](const char *arg) {
          m_help = true;
          m_help_str = arg ? arg : "";
          return true;
      }, OptionFlags::OptionalArgument);
      register_option("-V", "--version", "", "Show version and exit", [this](const char *arg) {
          m_version = true;
          return true;
      }, OptionFlags::NoArgument);
   }
};

struct ipxp_conf_t {
   uint32_t iqueue_size;
   uint32_t oqueue_size;
   uint32_t worker_cnt;
   uint32_t fps;
   uint32_t max_pkts;

   PluginManager mgr;
   struct Plugins {
      std::vector<InputPlugin *> input;
      std::vector<StoragePlugin *> storage;
      std::vector<OutputPlugin *> output;
      std::vector<ProcessPlugin *> process;
      std::vector<Plugin *> all;
   } active;

   std::vector<WorkPipeline> pipelines;
   std::vector<OutputWorker> outputs;

   std::vector<std::atomic<InputStats> *> input_stats;
   std::vector<std::atomic<OutputStats> *> output_stats;

   std::vector<std::shared_future<WorkerResult>> input_fut;
   std::vector<std::future<WorkerResult>> output_fut;  

   size_t pkt_bufsize;
   size_t blocks_cnt;
   size_t pkts_cnt;
   size_t pkt_data_cnt;

   PacketBlock *blocks;
   Packet *pkts;
   uint8_t *pkt_data;

   ipxp_conf_t() : iqueue_size(DEFAULT_IQUEUE_SIZE),
                   oqueue_size(DEFAULT_OQUEUE_SIZE),
                   worker_cnt(0), fps(0), max_pkts(0),
                   pkt_bufsize(1600), blocks_cnt(0), pkts_cnt(0), pkt_data_cnt(0), blocks(nullptr), pkts(nullptr), pkt_data(nullptr)
   {
   }

   ~ipxp_conf_t()
   {
      terminate_input = 1;
      for (auto &it : pipelines) {
         if (it.input.thread->joinable()) {
            it.input.thread->join();
         }
         delete it.input.plugin;
         delete it.input.thread;
         delete it.input.promise;
      }

      for (auto &it : pipelines) {
         delete it.storage.plugin;
      }

      for (auto &it : pipelines) {
         for (auto &itp : it.storage.plugins) {
            delete itp;
         }
      }

      terminate_export = 1;
      for (auto &it : outputs) {
         if (it.thread->joinable()) {
            it.thread->join();
         }
         delete it.thread;
         delete it.promise;
         delete it.plugin;
         ipx_ring_destroy(it.queue);
      }

      for (auto &it : input_stats) {
         delete it;
      }
      for (auto &it : output_stats) {
         delete it;
      }
   }
};

class IPXPError : public std::runtime_error {
public:
   explicit IPXPError(const std::string &msg) : std::runtime_error(msg) {};

   explicit IPXPError(const char *msg) : std::runtime_error(msg) {};
};

}
#endif /* IPXP_IPFIXPROBE_HPP */
