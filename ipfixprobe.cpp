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

#include "ipfixprobe.hpp"
#include "stacktrace.hpp"

namespace ipxp {

volatile sig_atomic_t stop = 0;
int terminate_export = 0;
int terminate_storage = 0;
int terminate_input = 0;

const uint32_t DEFAULT_IQUEUE_SIZE = 64;
const uint32_t DEFAULT_IQUEUE_BLOCK = 32;
const uint32_t DEFAULT_OQUEUE_SIZE = 16536;
const uint32_t DEFAULT_FPS = 0; // unlimited

/**
 * \brief Signal handler function.
 * \param [in] sig Signal number.
 */
void signal_handler(int sig)
{
#ifdef HAVE_LIBUNWIND
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
#ifdef HAVE_LIBUNWIND
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
      Plugin *p = conf.mgr.get(arg);
      if (p == nullptr) {
         std::cout << "No help available for " << arg << std::endl;
         return;
      }
      OptionsParser *parser = p->get_parser();
      parser->usage(std::cout);
      delete parser;
   }
}

void init_packets(ipxp_conf_t &conf)
{
   conf.blocks_cnt = (conf.iqueue_size + 1) * conf.worker_cnt;
   conf.pkts_cnt = conf.blocks_cnt * conf.iqueue_block;
   conf.pkt_data_cnt = conf.pkts_cnt * conf.pkt_bufsize;
   conf.blocks = new PacketBlock[conf.blocks_cnt];
   conf.pkts = new Packet[conf.pkts_cnt];
   conf.pkt_data = new uint8_t[conf.pkt_data_cnt];

   for (unsigned i = 0; i < conf.blocks_cnt; i++) {
      conf.blocks[i].pkts = conf.pkts + i * conf.iqueue_block;
      conf.blocks[i].cnt = 0;
      conf.blocks[i].size = conf.iqueue_block;
      for (unsigned j = 0; j < conf.iqueue_block; j++) {
         conf.blocks[i].pkts[j].buffer = static_cast<uint8_t *>(conf.pkt_data + conf.pkt_bufsize * (j + i * conf.iqueue_block));
         conf.blocks[i].pkts[j].buffer_size = conf.pkt_bufsize;
      }
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
      ProcessPlugin *process_plugin;
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
   OutputPlugin *output_plugin;
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
      std::promise<OutputStats> *output_stats = new std::promise<OutputStats>();
      OutputWorker tmp = {
              output_plugin,
              new std::thread(output_thread, output_plugin, output_queue, output_stats, conf.fps),
              output_stats,
              output_queue
      };
      conf.exporters.push_back(tmp);
      conf.output_fut.push_back(output_stats->get_future());
   }

   // Input
   size_t pipeline_idx = 0;
   for (auto &it : parser.m_input) {
      InputPlugin *input_plugin;
      StoragePlugin *storage_plugin;
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

      std::vector<ProcessPlugin *> storage_plugins;
      for (auto &it : *process_plugins) {
         ProcessPlugin *tmp = it.second->copy();
         storage_plugin->add_plugin(tmp);
         conf.active.process.push_back(tmp);
         conf.active.all.push_back(tmp);
         storage_plugins.push_back(tmp);
      }

      ipx_ring_t *input_queue = ipx_ring_init(conf.iqueue_size, 0);
      if (input_queue == nullptr) {
         throw IPXPError("unable to initialize ring buffer");
      }

      std::promise<InputStats> *input_stats = new std::promise<InputStats>();
      std::promise<StorageStats> *storage_stats = new std::promise<StorageStats>();
      conf.input_fut.push_back(input_stats->get_future());
      conf.storage_fut.push_back(storage_stats->get_future());

      WorkPipeline tmp = {
              {
                      input_plugin,
                      new std::thread(input_thread, input_plugin, &conf.blocks[pipeline_idx * (conf.iqueue_size + 1)],
                                      conf.iqueue_size + 1, conf.max_pkts, input_queue, input_stats),
                      input_stats,
              },
              {
                      storage_plugin,
                      new std::thread(storage_thread, storage_plugin, input_queue, storage_stats),
                      storage_stats,
                      storage_plugins
              },
              input_queue
      };
      conf.pipelines.push_back(tmp);
      pipeline_idx++;
   }

   return false;
}

void finish(ipxp_conf_t &conf)
{
   bool ok = true;

   terminate_input = 1;
   for (auto &it : conf.pipelines) {
      it.input.thread->join();
      it.input.plugin->close();
   }

   terminate_storage = 1;
   for (auto &it : conf.pipelines) {
      it.storage.thread->join();
      for (auto &itp : it.storage.plugins) {
         itp->close();
      }
   }

   terminate_export = 1;
   for (auto &it : conf.exporters) {
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
      std::setw(10) << "qtime" <<
      std::setw(7) << "status" << std::endl;

   int idx = 0;
   for (auto &it : conf.input_fut) {
      InputStats input = it.get();
      std::string status = "ok";
      if (input.error) {
         ok = false;
         status = input.msg;
      }
      std::cout <<
         std::setw(3) << idx++ << " " <<
         std::setw(9) << input.packets << " " <<
         std::setw(9) << input.parsed << " " <<
         std::setw(15) << input.bytes << " " <<
         std::setw(9) << input.qtime << " " <<
         std::setw(6) << status << std::endl;
   }

   std::ostringstream oss;
   oss << "Storage stats:" << std::endl <<
      std::setw(3) << "#" <<
      std::setw(7) << "status" << std::endl;

   idx = 0;
   bool storage_ok = true;
   for (auto &it : conf.storage_fut) {
      StorageStats storage = it.get();
      std::string status = "ok";
      if (storage.error) {
         ok = false;
         storage_ok = false;
         status = storage.msg;
      }
      oss <<
         std::setw(3) << idx++ << " " <<
         std::setw(6) << status << std::endl;
   }
   if (!storage_ok) {
      std::cout << oss.str();
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
      OutputStats output = it.get();
      std::string status = "ok";
      if (output.error) {
         ok = false;
         status = output.msg;
      }
      std::cout <<
         std::setw(3) << idx++ << " " <<
         std::setw(9) << output.biflows << " " <<
         std::setw(9) << output.packets << " " <<
         std::setw(15) << output.bytes << " " <<
         std::setw(9) << output.dropped << " " <<
         std::setw(6) << status << std::endl;
   }

   if (!ok) {
      throw IPXPError("one of the plugins exitted unexpectedly");
   }
}

void main_loop(ipxp_conf_t &conf)
{
   while (!stop) {
      for (auto &it : conf.input_fut) {
         std::future_status status = it.wait_for(std::chrono::seconds(0));
         if (status == std::future_status::ready) {
            stop = 1;
            break;
         }
      }
      usleep(1000);
   }

   finish(conf);
}

}
