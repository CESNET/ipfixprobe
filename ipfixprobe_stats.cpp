/**
 * \file ipfixprobe_stats.hpp
 * \brief Exporter live stats reading utility
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

#include <config.h>
#include <string>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <iomanip>

#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

#include "stats.hpp"

using namespace ipxp;

volatile sig_atomic_t stop = 0;

void signal_handler(int sig)
{
   stop = 1;
}

class IpfixStatsParser : public OptionsParser {
public:
   pid_t m_pid;
   bool m_one;
   bool m_help;

   IpfixStatsParser() : OptionsParser("ipfixprobe_stats", "Read statistics from running ipfixprobe exporter"),
                        m_pid(0), m_one(false), m_help(false)
   {
      m_delim = ' ';

      register_option("-p", "--pid", "NUM", "ipfixprobe exporter PID number", [this](const char *arg) {
            try { m_pid = str2num<decltype(m_pid)>(arg); } catch (
                  std::invalid_argument &e) { return false; }
            return true;
      }, OptionFlags::RequiredArgument);
      register_option("-1", "--one", "", "Print stats and exit", [this](const char *arg) {
            m_one = true;
            return true;
      }, OptionFlags::NoArgument);
      register_option("-h", "--help", "", "Print help", [this](const char *arg) {
            m_help = true;
            return true;
      }, OptionFlags::NoArgument);
   }
};

static void error(const std::string &msg)
{
   std::cerr << "Error: " << msg << std::endl;
}

int main(int argc, char *argv[])
{
   size_t lines_written = 0;
   int fd = -1;
   int status = EXIT_SUCCESS;
   uint8_t buffer[100000];
   msg_header_t *hdr = (msg_header_t *) buffer;
   std::string path;
   IpfixStatsParser parser;


   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   try {
      parser.parse(argc - 1, const_cast<const char **>(argv) + 1);

      if (parser.m_help) {
         parser.usage(std::cout, 0);
         goto EXIT;
      }

      path = DEFAULTSOCKETDIR "/ipfixprobe_" + std::to_string(parser.m_pid) + ".sock";
      fd = connect_to_exporter(path.c_str());
      if (fd == -1) {
         error("connecting to exporter");
         goto EXIT;
      }
   } catch (std::runtime_error &e) {
      error(e.what());
      status = EXIT_FAILURE;
      goto EXIT;
   }

   while (!stop) {
      *(uint32_t *) buffer = MSG_MAGIC;
      // Send stats data request
      if (send_data(fd, sizeof(uint32_t), buffer)) {
         status = EXIT_FAILURE;
         break;
      }

      // Receive message header
      if (recv_data(fd, sizeof(msg_header_t), buffer)) {
         status = EXIT_FAILURE;
         break;
      }

      // Check if message header is correct
      if (hdr->magic != MSG_MAGIC) {
         error("received data are invalid");
         status = EXIT_FAILURE;
         break;
      }

      // Receive array of various stats from exporter
      if (recv_data(fd, hdr->size, (buffer + sizeof(msg_header_t)))) {
         status = EXIT_FAILURE;
         break;
      }

      // Erase previous stats output lines
      for (size_t i = 0; i < lines_written; i++) {
         std::cout << "\033[A\33[2K\r";
      }

      // Process received stats
      std::cout << "Input stats:" << std::endl <<
         std::setw(3) << "#" <<
         std::setw(10) << "packets" <<
         std::setw(10) << "parsed" <<
         std::setw(16) << "bytes" <<
         std::setw(10) << "dropped" <<
         std::setw(10) << "qtime" << std::endl;

      uint8_t *data = buffer + sizeof(msg_header_t);
      size_t idx = 0;
      for (size_t i = 0; i < hdr->inputs; i++) {
         InputStats *stats = (InputStats *) data;
         data += sizeof(InputStats);
         std::cout <<
            std::setw(3) << idx++ << " " <<
            std::setw(9) << stats->packets << " " <<
            std::setw(9) << stats->parsed << " " <<
            std::setw(15) << stats->bytes << " " <<
            std::setw(9) << stats->dropped << " " <<
            std::setw(9) << stats->qtime << " " << std::endl;
      }

      std::cout << "Output stats:" << std::endl <<
         std::setw(3) << "#" <<
         std::setw(10) << "biflows" <<
         std::setw(10) << "packets" <<
         std::setw(16) << "bytes" <<
         std::setw(10) << "dropped" << std::endl;

      idx = 0;
      for (size_t i = 0; i < hdr->outputs; i++) {
         OutputStats *stats = (OutputStats *) data;
         data += sizeof(OutputStats);
         std::cout <<
            std::setw(3) << idx++ << " " <<
            std::setw(9) << stats->biflows << " " <<
            std::setw(9) << stats->packets << " " <<
            std::setw(15) << stats->bytes << " " <<
            std::setw(9) << stats->dropped << " " << std::endl;
      }

      if (parser.m_one) {
         break;
      }

      lines_written = hdr->inputs + hdr->outputs + 4;
      usleep(1000000);
   }
EXIT:
   if (fd != -1) {
      close(fd);
   }
   return status;
}
