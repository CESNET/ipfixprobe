/**
 * \file osqueryplugin.cpp
 * \brief Plugin for parsing osquery traffic.
 * \author Anton Aheyeu aheyeant@fit.cvut.cz
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
 * This software is provided as is'', and any express or implied
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

#include <iostream>
#include <sstream>

#include "osqueryplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define OSQUERY_UNIREC_TEMPLATE "OSQUERY_PROGRAM_NAME,OSQUERY_USERNAME,OSQUERY_OS_NAME,OSQUERY_OS_MAJOR,OSQUERY_OS_MINOR,OSQUERY_OS_BUILD,OSQUERY_OS_PLATFORM,OSQUERY_OS_PLATFORM_LIKE,OSQUERY_OS_ARCH,OSQUERY_KERNEL_VERSION,OSQUERY_SYSTEM_HOSTNAME"

UR_FIELDS (
   string OSQUERY_PROGRAM_NAME,
   string OSQUERY_USERNAME,
   string OSQUERY_OS_NAME,
   uint16 OSQUERY_OS_MAJOR,
   uint16 OSQUERY_OS_MINOR,
   string OSQUERY_OS_BUILD,
   string OSQUERY_OS_PLATFORM,
   string OSQUERY_OS_PLATFORM_LIKE,
   string OSQUERY_OS_ARCH,
   string OSQUERY_KERNEL_VERSION,
   string OSQUERY_SYSTEM_HOSTNAME
)

OSQUERYPlugin::OSQUERYPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

OSQUERYPlugin::OSQUERYPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

void OSQUERYPlugin::init()
{
   osqueryFatalError = popen2("osqueryi --json", &inputFD, &outputFD) <= 0;
   osqueryFail = false;
   buffer = NULL;
   numberOfQueries = 0;
   if (!osqueryFatalError)
   {
      buffer = new char[BUFFER_SIZE];
      pollFDS = new pollfd;
      recordExtOsquery = new RecordExtOSQUERY;
      pollFDS->fd = outputFD;
      pollFDS->events = POLLIN;
      pollFDS->revents = 0;


      const string query = "SELECT ov.name, ov.major, ov.minor, ov.build, ov.platform, ov.platform_like, ov.arch, ki.version, si.hostname FROM os_version AS ov, kernel_info AS ki, system_info AS si;\r\n";
      if (!getResponse(query))
      {
         osqueryFatalError = true;
      } else {
          if (!parseJsonOSVersion()) {
              if (!getResponse(query) || !parseJsonOSVersion()) {
                  osqueryFatalError = true;
              }
          }
      }
   }
}

int OSQUERYPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int OSQUERYPlugin::post_create(Flow &rec, const Packet &pkt)
{
   stringstream ss;
   ss << ((rec.src_ip.v4)       & 0x000000ff) << "."
      << ((rec.src_ip.v4 >> 8)  & 0x000000ff) << "."
      << ((rec.src_ip.v4 >> 16) & 0x000000ff) << "."
      << ((rec.src_ip.v4 >> 24) & 0x000000ff);
   string ssrc_ip = ss.str();

   ss.str(string());
   ss << ((rec.dst_ip.v4)       & 0x000000ff) << "."
      << ((rec.dst_ip.v4 >> 8)  & 0x000000ff) << "."
      << ((rec.dst_ip.v4 >> 16) & 0x000000ff) << "."
      << ((rec.dst_ip.v4 >> 24) & 0x000000ff);
   string sdst_ip = ss.str();

   ss.str(string());
   ss << rec.src_port;
   string ssrc_port = ss.str();

   ss.str(string());
   ss << rec.dst_port;
   string sdst_port = ss.str();

   string query = "SELECT p.name, u.username FROM processes AS p INNER JOIN users AS u ON p.uid=u.uid WHERE p.pid=(SELECT pos.pid FROM process_open_sockets AS pos WHERE "
                  "local_address='" + ssrc_ip + "' AND " +
                  "remote_address='" + sdst_ip + "' AND " +
                  "local_port='" + ssrc_port + "' AND " +
                  "remote_port='" + sdst_port + "'  LIMIT 1);";

   getResponseFromOsquery(query);
   if (!osqueryFatalError && !osqueryFail) {
       parseJsonAboutProgram();
   }

   RecordExtOSQUERY *record = new RecordExtOSQUERY(recordExtOsquery);
   rec.addExtension(record);

   numberOfQueries++;
   return 0;
}

int OSQUERYPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int OSQUERYPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void OSQUERYPlugin::pre_export(Flow &rec)
{
}

void OSQUERYPlugin::finish()
{
   if (buffer) {
      delete[] buffer;
      delete pollFDS;
      delete recordExtOsquery;
      close(inputFD);
      close(outputFD);
   }

   if (print_stats) {
       cout << "OSQUERY plugin stats:" << endl;
       cout << "Number of queries:" << numberOfQueries << endl;
   }
}

const char *ipfix_osquery_template[] = {
   IPFIX_OSQUERY_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **OSQUERYPlugin::get_ipfix_string()
{
   return ipfix_osquery_template;
}

string OSQUERYPlugin::get_unirec_field_string()
{
   return OSQUERY_UNIREC_TEMPLATE;
}

bool OSQUERYPlugin::include_basic_flow_fields()
{
   return true;
}

bool OSQUERYPlugin::getResponse(const string &query) {
    if (osqueryFatalError) {
        return false;
    }

    osqueryFail = false;

    getResponseFromOsquery(query);
    if (osqueryFatalError) {
        return false;
    }
    if (!osqueryFail) {
        return true;
    }

    close(inputFD);
    close(outputFD);

    osqueryFatalError = popen2("osqueryi --json", &inputFD, &outputFD) <= 0;
    if (osqueryFatalError) {
        return false;
    }

    getResponseFromOsquery(query);
    if (osqueryFatalError || osqueryFail) {
        return false;
    }
    return true;
}

void OSQUERYPlugin::getResponseFromOsquery(const string &query)
{
   if (osqueryFatalError) {
      return;
   }

   osqueryFail = false;

   ssize_t numWrite = write(inputFD, query.c_str(), query.length());
   if (numWrite == -1) {
      osqueryFail = true;
      return;
   }

   int ret = poll(pollFDS, 1, POLL_TIMEOUT);
   if (ret == -1 || ret == 0) {
      osqueryFail = true;
      return;
   }

   if (pollFDS[0].revents & POLLIN) {
      pollFDS[0].revents = 0;

      size_t bytes_read = 0;
      while(true) {
         if (bytes_read + READ_SIZE < BUFFER_SIZE) {
            ssize_t n = read(outputFD, buffer + bytes_read, READ_SIZE);
            if (n < 0) {
               osqueryFail = true;
               return;
            }

            bytes_read = bytes_read + n;
            if (buffer[bytes_read - 2] == ']') {
               buffer[bytes_read] = 0;
               break;
            }
         } else {
            ssize_t n = read(outputFD, buffer, READ_SIZE);
            if (n < 0) {
               osqueryFail = true;
               return;
            }
            if (n > 1 && buffer[n - 2] == ']') {
               buffer[bytes_read] = 0;
               osqueryFail = true;
               return;
            }

         }
      }

      buffer[bytes_read] = 0;
      return;
   }
   osqueryFatalError = true;
   return;
}

bool OSQUERYPlugin::parseJsonOSVersion()
{
   int pos = 1;
   int count = 0;
   string key, value;
   while (true) {
      key.clear();
      value.clear();
      pos = parseJsonItem(pos, key, value);
      if (pos < 0) {
         return false;
      }
      if (pos == 0) {
         return count == 9;
      }
      if (key == "arch") {
         recordExtOsquery->os_arch = string(value);
         count++;
      } else if (key == "build") {
         recordExtOsquery->os_build = value;
         count++;
      } else if (key == "hostname") {
         recordExtOsquery->system_hostname = value;
         count++;
      } else if (key == "major") {
         recordExtOsquery->os_major = atoi(value.c_str());
         count++;
      } else if (key == "minor") {
         recordExtOsquery->os_minor = atoi(value.c_str());
         count++;
      } else if (key == "name") {
         recordExtOsquery->os_name = value;
         count++;
      } else if (key == "platform") {
         recordExtOsquery->os_platform = value;
         count++;
      } else if (key == "platform_like") {
         recordExtOsquery->os_platform_like = value;
         count++;
      } else if (key == "version") {
         recordExtOsquery->kernel_version = value;
         count++;
      } else {
         return false;
      }
   }
}

bool OSQUERYPlugin::parseJsonAboutProgram()
{
   int pos = 1;
   int count = 0;
   string key, value;
   while (true) {
      key.clear();
      value.clear();
      pos = parseJsonItem(pos, key, value);
      if (pos < 0) {
         return false;
      }
      if (pos == 0) {
         return count == 2;
      }

      if (key == "name") {
         recordExtOsquery->program_name = value;
         count++;
      } else if (key == "username") {
         recordExtOsquery->username = value;
         count++;
      } else {
         return false;
      }
   }
}

int OSQUERYPlugin::parseJsonItem(int from, string &key, string &value)
{
   int pos = parseString(from, key);
   if (pos < 0) {
      return -1;
   }
   if (pos == 0) {
      return 0;
   }
   if (buffer[pos] != ':') {
      return -1;
   }

   pos = parseString(pos, value);
   if (pos <= 0) {
      return -1;
   }
   return pos;
}

int OSQUERYPlugin::parseString(int from, string &str)
{
   int pos = from;
   bool findQuotes = false;
   char c;
   while (true) {
      c = buffer[pos];
      pos++;
       if (c == 0) {
           return -1;
       } else if (c == '}') {
           return 0;
       } else if (c == '\"') {
           if (!findQuotes) {
               findQuotes = true;
           } else {
               break;
           }
       } else if (findQuotes) {
           str += c;
       }
   }
   return pos;
}

pid_t OSQUERYPlugin::popen2(const char *command, int *inFD, int *outFD)
{
    int p_stdin[2], p_stdout[2];
    pid_t pid;

    if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0) {
        return -1;
    }

    pid = fork();

    if (pid < 0) {
        return pid;
    } else if (pid == 0) {
        close(p_stdin[WRITE]);
        dup2(p_stdin[READ], READ);
        close(p_stdout[READ]);
        dup2(p_stdout[WRITE], WRITE);
        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("execl");
        exit(1);
    }

    inFD == NULL ? close(p_stdin[WRITE]) : *inFD = p_stdin[WRITE];
    outFD == NULL ? close(p_stdout[READ]) : *outFD = p_stdout[READ];

    return pid;
}

