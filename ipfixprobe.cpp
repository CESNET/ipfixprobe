/**
 * \file ipfixprobe.cpp
 * \brief Main exporter objects source
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

#include <config.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <memory>
#include <thread>
#include <future>
#include <signal.h>
#include <poll.h>

#ifdef WITH_DPDK
#include <rte_eal.h>
#include <rte_errno.h>
#endif

#include "ipfixprobe.hpp"
#ifdef WITH_LIBUNWIND
#include "stacktrace.hpp"
#endif
#include "stats.hpp"

namespace ipxp {

volatile sig_atomic_t stop = 0;

volatile sig_atomic_t terminate_export = 0;
volatile sig_atomic_t terminate_input = 0;

const uint32_t DEFAULT_IQUEUE_SIZE = 64;
const uint32_t DEFAULT_OQUEUE_SIZE = 16536;
const uint32_t DEFAULT_FPS = 0; // unlimited

/**
 * \brief Signal handler function.
 * \param [in] sig Signal number.
 */
void signal_handler(int sig)
{
#ifdef WITH_LIBUNWIND
   if (sig == SIGSEGV) {
      st_dump(STDERR_FILENO, sig);
      abort();
   }
#endif
   stop = 1;
}

void register_handlers()
{
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
#ifdef WITH_LIBUNWIND
   signal(SIGSEGV, signal_handler);
#endif
#ifdef WITH_NEMEA
   signal(SIGPIPE, SIG_IGN);
#endif
}

void error(std::string msg)
{
   std::cerr << "Error: " << msg << std::endl;
}

template<typename T>
static void print_plugins_help(std::vector<Plugin *> &plugins)
{
   for (auto &it : plugins) {
      if (dynamic_cast<T *>(it)) {
         OptionsParser *parser = it->get_parser();
         parser->usage(std::cout);
         std::cout << std::endl;
         delete parser;
      }
   }
}

void print_help(ipxp_conf_t &conf, const std::string &arg)
{
   auto deleter = [&](std::vector<Plugin *> *p) {
      for (auto &it : *p) {
         delete it;
      }
      delete p;
   };
   auto plugins = std::unique_ptr<std::vector<Plugin *>, decltype(deleter)>(new std::vector<Plugin*>(conf.mgr.get()), deleter);

   if (arg == "input") {
      print_plugins_help<InputPlugin>(*plugins);
   } else if (arg == "storage") {
      print_plugins_help<StoragePlugin>(*plugins);
   } else if (arg == "output") {
      print_plugins_help<OutputPlugin>(*plugins);
   } else if (arg == "process") {
      print_plugins_help<ProcessPlugin>(*plugins);
   } else {
      Plugin *p;
      try {
         p = conf.mgr.get(arg);
         if (p == nullptr) {
            std::cout << "No help available for " << arg << std::endl;
            return;
         }
      } catch (PluginManagerError &e) {
         error(std::string("when loading plugin: ") + e.what());
         return;
      }
      OptionsParser *parser = p->get_parser();
      parser->usage(std::cout);
      delete parser;
      delete p;
   }
}

void process_plugin_argline(const std::string &args, std::string &plugin, std::string &params)
{
   size_t delim;

   params = args;
   delim = params.find(OptionsParser::DELIM);

   plugin = params.substr(0, delim);
   params.erase(0, delim == std::string::npos ? delim : delim + 1);

   trim_str(plugin);
   trim_str(params);
}

bool process_plugin_args(ipxp_conf_t &conf, IpfixprobeOptParser &parser)
{
   auto deleter = [&](OutputPlugin::Plugins *p) {
      for (auto &it : *p) {
         delete it.second;
      }
      delete p;
   };
   auto process_plugins = std::unique_ptr<OutputPlugin::Plugins, decltype(deleter)>(new OutputPlugin::Plugins(), deleter);
   std::string storage_name = "cache";
   std::string storage_params = "";
   std::string output_name = "ipfix";
   std::string output_params = "";

   if (parser.m_storage.size()) {
      process_plugin_argline(parser.m_storage[0], storage_name, storage_params);
   }
   if (parser.m_output.size()) {
      process_plugin_argline(parser.m_output[0], output_name, output_params);
   }

   // Process
   for (auto &it : parser.m_process) {
      ProcessPlugin *process_plugin = nullptr;
      std::string process_params;
      std::string process_name;
      process_plugin_argline(it, process_name, process_params);
      for (auto &it : *process_plugins) {
         std::string plugin_name = it.first;
         if (plugin_name == process_name) {
            throw IPXPError(process_name + " plugin was specified multiple times");
         }
      }
      if (process_name == BASIC_PLUGIN_NAME) {
         continue;
      }
      try {
         process_plugin = dynamic_cast<ProcessPlugin *>(conf.mgr.get(process_name));
         if (process_plugin == nullptr) {
            throw IPXPError("invalid processing plugin " + process_name);
         }

         process_plugin->init(process_params.c_str());
         process_plugins->push_back(std::make_pair(process_name, process_plugin));
      } catch (PluginError &e) {
         delete process_plugin;
         throw IPXPError(process_name + std::string(": ") + e.what());
      } catch (PluginExit &e) {
         delete process_plugin;
         return true;
      } catch (PluginManagerError &e) {
         throw IPXPError(process_name + std::string(": ") + e.what());
      }
   }

   // Output
   ipx_ring_t *output_queue = ipx_ring_init(conf.oqueue_size, 1);
   if (output_queue == nullptr) {
      throw IPXPError("unable to initialize ring buffer");
   }
   OutputPlugin *output_plugin = nullptr;
   try {
      output_plugin = dynamic_cast<OutputPlugin *>(conf.mgr.get(output_name));
      if (output_plugin == nullptr) {
         ipx_ring_destroy(output_queue);
         throw IPXPError("invalid output plugin " + output_name);
      }

      output_plugin->init(output_params.c_str(), *process_plugins);
      conf.active.output.push_back(output_plugin);
      conf.active.all.push_back(output_plugin);
   } catch (PluginError &e) {
      ipx_ring_destroy(output_queue);
      delete output_plugin;
      throw IPXPError(output_name + std::string(": ") + e.what());
   } catch (PluginExit &e) {
      ipx_ring_destroy(output_queue);
      delete output_plugin;
      return true;
   } catch (PluginManagerError &e) {
      throw IPXPError(output_name + std::string(": ") + e.what());
   }

   {
      std::promise<WorkerResult> *output_res = new std::promise<WorkerResult>();
      auto output_stats = new std::atomic<OutputStats>();
      conf.output_stats.push_back(output_stats);
      OutputWorker tmp = {
              output_plugin,
              new std::thread(output_worker, output_plugin, output_queue, output_res, output_stats, conf.fps),
              output_res,
              output_stats,
              output_queue
      };
      conf.outputs.push_back(tmp);
      conf.output_fut.push_back(output_res->get_future());
   }

   // Input
   size_t pipeline_idx = 0;
   for (auto &it : parser.m_input) {
      InputPlugin *input_plugin = nullptr;
      StoragePlugin *storage_plugin = nullptr;
      std::string input_params;
      std::string input_name;
      process_plugin_argline(it, input_name, input_params);

      try {
         input_plugin = dynamic_cast<InputPlugin *>(conf.mgr.get(input_name));
         if (input_plugin == nullptr) {
            throw IPXPError("invalid input plugin " + input_name);
         }
         input_plugin->init(input_params.c_str());
         conf.active.input.push_back(input_plugin);
         conf.active.all.push_back(input_plugin);
      } catch (PluginError &e) {
         delete input_plugin;
         throw IPXPError(input_name + std::string(": ") + e.what());
      } catch (PluginExit &e) {
         delete input_plugin;
         return true;
      } catch (PluginManagerError &e) {
         throw IPXPError(input_name + std::string(": ") + e.what());
      }

      try {
         storage_plugin = dynamic_cast<StoragePlugin *>(conf.mgr.get(storage_name));
         if (storage_plugin == nullptr) {
            throw IPXPError("invalid storage plugin " + storage_name);
         }
         storage_plugin->set_queue(output_queue);
         storage_plugin->init(storage_params.c_str());
         conf.active.storage.push_back(storage_plugin);
         conf.active.all.push_back(storage_plugin);
      } catch (PluginError &e) {
         delete storage_plugin;
         throw IPXPError(storage_name + std::string(": ") + e.what());
      } catch (PluginExit &e) {
         delete storage_plugin;
         return true;
      } catch (PluginManagerError &e) {
         throw IPXPError(storage_name + std::string(": ") + e.what());
      }

      std::vector<ProcessPlugin *> storage_process_plugins;
      for (auto &it : *process_plugins) {
         ProcessPlugin *tmp = it.second->copy();
         storage_plugin->add_plugin(tmp);
         conf.active.process.push_back(tmp);
         conf.active.all.push_back(tmp);
         storage_process_plugins.push_back(tmp);
      }

      std::promise<WorkerResult> *input_res = new std::promise<WorkerResult>();
      conf.input_fut.push_back(input_res->get_future());

      auto input_stats = new std::atomic<InputStats>();
      conf.input_stats.push_back(input_stats);

      WorkPipeline tmp = {
         {
            input_plugin,
            new std::thread(input_storage_worker, input_plugin, storage_plugin, conf.iqueue_size, 
               conf.max_pkts, input_res, input_stats),
            input_res,
            input_stats
         },
         {
            storage_plugin,
            storage_process_plugins
         }
      };
      conf.pipelines.push_back(tmp);
      pipeline_idx++;
   }

   return false;
}

void finish(ipxp_conf_t &conf)
{
   bool ok = true;

   // Terminate all inputs
   terminate_input = 1;
   for (auto &it : conf.pipelines) {
      it.input.thread->join();
      it.input.plugin->close();
   }

   // Terminate all storages
   for (auto &it : conf.pipelines) {
      for (auto &itp : it.storage.plugins) {
         itp->close();
      }
   }

   // Terminate all outputs
   terminate_export = 1;
   for (auto &it : conf.outputs) {
      it.thread->join();
   }

   for (auto &it : conf.pipelines) {
      it.storage.plugin->close();
   }

   std::cout << "Input stats:" << std::endl <<
      std::setw(3) << "#" <<
      std::setw(10) << "packets" <<
      std::setw(10) << "parsed" <<
      std::setw(16) << "bytes" <<
      std::setw(10) << "dropped" <<
      std::setw(10) << "qtime" <<
      std::setw(7) << "status" << std::endl;

   int idx = 0;
   for (auto &it : conf.input_fut) {
      WorkerResult res = it.get();
      std::string status = "ok";
      if (res.error) {
         ok = false;
         status = res.msg;
      }
      InputStats stats = conf.input_stats[idx]->load();
      std::cout <<
         std::setw(3) << idx++ << " " <<
         std::setw(9) << stats.packets << " " <<
         std::setw(9) << stats.parsed << " " <<
         std::setw(15) << stats.bytes << " " <<
         std::setw(9) << stats.dropped << " " <<
         std::setw(9) << stats.qtime << " " <<
         std::setw(6) << status << std::endl;
   }

   std::cout << "Output stats:" << std::endl <<
      std::setw(3) << "#" <<
      std::setw(10) << "biflows" <<
      std::setw(10) << "packets" <<
      std::setw(16) << "bytes" <<
      std::setw(10) << "dropped" <<
      std::setw(7) << "status" << std::endl;

   idx = 0;
   for (auto &it : conf.output_fut) {
      WorkerResult res = it.get();
      std::string status = "ok";
      if (res.error) {
         ok = false;
         status = res.msg;
      }
      OutputStats stats = conf.output_stats[idx]->load();
      std::cout <<
         std::setw(3) << idx++ << " " <<
         std::setw(9) << stats.biflows << " " <<
         std::setw(9) << stats.packets << " " <<
         std::setw(15) << stats.bytes << " " <<
         std::setw(9) << stats.dropped << " " <<
         std::setw(6) << status << std::endl;
   }

   if (!ok) {
      throw IPXPError("one of the plugins exitted unexpectedly");
   }
}

void serve_stat_clients(ipxp_conf_t &conf, struct pollfd pfds[2])
{
   uint8_t buffer[100000];
   size_t written = 0;
   msg_header_t *hdr = (msg_header_t *) buffer;
   int ret = poll(pfds, 2, 0);
   if (ret <= 0) {
      return;
   }
   if (pfds[1].fd > 0 && pfds[1].revents & POLL_IN) {
      ret = recv_data(pfds[1].fd, sizeof(uint32_t), buffer);
      if (ret < 0) {
         // Client disconnected
         close(pfds[1].fd);
         pfds[1].fd = -1;
      } else {
         if (*((uint32_t *) buffer) != MSG_MAGIC) {
            return;
         }
         // Received stats request from client
         written += sizeof(msg_header_t);
         for (auto &it : conf.input_stats) {
            InputStats stats = it->load();
            *(InputStats *)(buffer + written) = stats;
            written += sizeof(InputStats);
         }
         for (auto &it : conf.output_stats) {
            OutputStats stats = it->load();
            *(OutputStats *)(buffer + written) = stats;
            written += sizeof(OutputStats);
         }

         hdr->magic = MSG_MAGIC;
         hdr->size = written - sizeof(msg_header_t);
         hdr->inputs = conf.input_stats.size();
         hdr->outputs = conf.output_stats.size();

         send_data(pfds[1].fd, written, buffer);
      }
   }

   if (pfds[0].revents & POLL_IN) {
      int fd = accept(pfds[0].fd, NULL, NULL);
      if (pfds[1].fd == -1) {
         pfds[1].fd = fd;
      } else if (fd != -1) {
         // Close incoming connection
         close(fd);
      }
   }
}

void main_loop(ipxp_conf_t &conf)
{
   std::vector<std::shared_future<WorkerResult>*> futs;
   for (auto &it : conf.input_fut) {
      futs.push_back(&it);
   }

   struct pollfd pfds[2] = {
      {.fd = -1, .events = POLL_IN}, // Server
      {.fd = -1, .events = POLL_IN} // Client
   };

   std::string sock_path = create_sockpath(std::to_string(getpid()).c_str());
   pfds[0].fd = create_stats_sock(sock_path.c_str());
   if (pfds[0].fd < 0) {
      error("Unable to create stats socket " + sock_path);
   }

   while (!stop && futs.size()) {
      serve_stat_clients(conf, pfds);

      for (auto it = futs.begin(); it != futs.end(); it++) {
         std::future_status status = (*it)->wait_for(std::chrono::seconds(0));
         if (status == std::future_status::ready) {
            WorkerResult res = (*it)->get();
            if (!res.error) {
               it = futs.erase(it);
               break;
            }
            stop = 1;
            break;
         }
      }
      for (auto &it : conf.output_fut) {
         std::future_status status = it.wait_for(std::chrono::seconds(0));
         if (status == std::future_status::ready) {
            stop = 1;
            break;
         }
      }

      usleep(1000);
   }

   if (pfds[0].fd != -1) {
      close(pfds[0].fd);
   }
   if (pfds[1].fd != -1) {
      close(pfds[1].fd);
   }
   unlink(sock_path.c_str());
   finish(conf);
}

int run(int argc, char *argv[])
{
   IpfixprobeOptParser parser;
   ipxp_conf_t conf;
   int status = EXIT_SUCCESS;

   register_handlers();

#ifdef WITH_DPDK
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Cannot initialize RTE_EAL: %s\n", rte_strerror(rte_errno));
    }
    argc -= ret;
    argv += ret;
#endif

   try {
      parser.parse(argc - 1, const_cast<const char **>(argv) + 1);
   } catch (ParserError &e) {
      error(e.what());
      status = EXIT_FAILURE;
      goto EXIT;
   }

   if (parser.m_help) {
      if (parser.m_help_str.empty()) {
         parser.usage(std::cout, 0, PACKAGE_NAME);
      } else {
         print_help(conf, parser.m_help_str);
      }
      goto EXIT;
   }
   if (parser.m_version) {
      std::cout << PACKAGE_VERSION << std::endl;
      goto EXIT;
   }
   if (parser.m_storage.size() > 1 || parser.m_output.size() > 1) {
      error("only one storage and output plugin can be specified");
      status = EXIT_FAILURE;
      goto EXIT;
   }
   if (parser.m_input.size() == 0) {
      error("specify at least one input plugin");
      status = EXIT_FAILURE;
      goto EXIT;
   }

   if (parser.m_daemon) {
      if (daemon(1, 0) == -1) {
         error("failed to run as a standalone process");
         status = EXIT_FAILURE;
         goto EXIT;
      }
   }
   if (!parser.m_pid.empty()) {
      std::ofstream pid_file(parser.m_pid, std::ofstream::out);
      if (pid_file.fail()) {
         error("failed to write pid file");
         status = EXIT_FAILURE;
         goto EXIT;
      }
      pid_file << getpid();
      pid_file.close();
   }

   if (parser.m_iqueue < 1) {
      error("input queue size must be at least 1 record");
      status = EXIT_FAILURE;
      goto EXIT;
   }
   if (parser.m_oqueue < 1) {
      error("output queue size must be at least 1 record");
      status = EXIT_FAILURE;
      goto EXIT;
   }

   conf.worker_cnt = parser.m_input.size();
   conf.iqueue_size = parser.m_iqueue;
   conf.oqueue_size = parser.m_oqueue;
   conf.fps = parser.m_fps;
   conf.pkt_bufsize = parser.m_pkt_bufsize;
   conf.max_pkts = parser.m_max_pkts;

   try {
      if (process_plugin_args(conf, parser)) {
         goto EXIT;
      }
      main_loop(conf);
   } catch (std::system_error &e) {
      error(e.what());
      status = EXIT_FAILURE;
      goto EXIT;
   } catch (std::bad_alloc &e) {
      error("not enough memory");
      status = EXIT_FAILURE;
      goto EXIT;
   } catch (IPXPError &e) {
      error(e.what());
      status = EXIT_FAILURE;
      goto EXIT;
   }

EXIT:
#ifdef WITH_DPDK
    rte_eal_cleanup();
#endif

   if (!parser.m_pid.empty()) {
      unlink(parser.m_pid.c_str());
   }
   return status;
}

}
