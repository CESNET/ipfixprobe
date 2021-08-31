/**
 * \file main.cpp
 * \brief Main file of the ipfixprobe exporter
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

#include "ipfixprobe.hpp"

int main(int argc, char *argv[])
{
   ipxp::IpfixprobeOptParser parser;
   ipxp::ipxp_conf_t conf;
   int status = EXIT_SUCCESS;

   ipxp::register_handlers();

   try {
      parser.parse(argc - 1, const_cast<const char **>(argv) + 1);
   } catch (ipxp::ParserError &e) {
      ipxp::error(e.what());
      status = EXIT_FAILURE;
      goto EXIT;
   }

   if (parser.m_help) {
      if (parser.m_help_str.empty()) {
         parser.usage(std::cout, 0, PACKAGE_NAME);
      } else {
         ipxp::print_help(conf, parser.m_help_str);
      }
      goto EXIT;
   }
   if (parser.m_version) {
      std::cout << PACKAGE_VERSION << std::endl;
      goto EXIT;
   }
   if (parser.m_storage.size() > 1 || parser.m_output.size() > 1) {
      ipxp::error("only one storage and output plugin can be specified");
      status = EXIT_FAILURE;
      goto EXIT;
   }
   if (parser.m_input.size() == 0) {
      ipxp::error("specify at least one input plugin");
      status = EXIT_FAILURE;
      goto EXIT;
   }

   if (parser.m_daemon) {
      if (daemon(1, 0) == -1) {
         ipxp::error("failed to run as a standalone process");
         status = EXIT_FAILURE;
         goto EXIT;
      }
   }
   if (!parser.m_pid.empty()) {
      std::ofstream pid_file(parser.m_pid, std::ofstream::out);
      if (pid_file.fail()) {
         ipxp::error("failed to write pid file");
         status = EXIT_FAILURE;
         goto EXIT;
      }
      pid_file << getpid();
      pid_file.close();
   }

   if (parser.m_iqueue < 1) {
      ipxp::error("input queue size must be at least 1 record");
      status = EXIT_FAILURE;
      goto EXIT;
   }
   if (parser.m_oqueue < 1) {
      ipxp::error("output queue size must be at least 1 record");
      status = EXIT_FAILURE;
      goto EXIT;
   }

   conf.worker_cnt = parser.m_input.size();
   conf.iqueue_block = parser.m_iqueue_block;
   conf.iqueue_size = parser.m_iqueue;
   conf.oqueue_size = parser.m_oqueue;
   conf.fps = parser.m_fps;
   conf.pkt_bufsize = parser.m_pkt_bufsize;
   conf.max_pkts = parser.m_max_pkts;

   try {
      ipxp::init_packets(conf);
      if (ipxp::process_plugin_args(conf, parser)) {
         goto EXIT;
      }
      ipxp::main_loop(conf);
   } catch (std::bad_alloc &e) {
      ipxp::error("not enough memory");
      status = EXIT_FAILURE;
      goto EXIT;
   } catch (ipxp::IPXPError &e) {
      ipxp::error(e.what());
      status = EXIT_FAILURE;
      goto EXIT;
   }

EXIT:
   if (!parser.m_pid.empty()) {
      unlink(parser.m_pid.c_str());
   }
   return status;
}
