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
#include <iomanip>
#include <sstream>
#include <cstring>
#include <cstdio>

#include "osqueryplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define OSQUERY_UNIREC_TEMPLATE \
   "OSQUERY_PROGRAM_NAME,OSQUERY_USERNAME,OSQUERY_OS_NAME,OSQUERY_OS_MAJOR,OSQUERY_OS_MINOR,OSQUERY_OS_BUILD,OSQUERY_OS_PLATFORM,OSQUERY_OS_PLATFORM_LIKE,OSQUERY_OS_ARCH,OSQUERY_KERNEL_VERSION,OSQUERY_SYSTEM_HOSTNAME"

#define HEX(x) setw(2) << setfill('0') << hex << (int) (x)

UR_FIELDS(
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

OSQUERYPlugin::OSQUERYPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(
      plugin_options)
{
   print_stats = module_options.print_stats;
}

void OSQUERYPlugin::init()
{
   numberOfSuccessfullyRequests = 0;
   manager = new OsqueryRequestManager();
   manager->readInfoAboutOS();
}

int OSQUERYPlugin::post_create(Flow &rec, const Packet &pkt)
{
   ConvertedFlowData flowDataIPv4(rec.src_ip.v4, rec.dst_ip.v4, rec.src_port, rec.dst_port);

   if (manager->readInfoAboutProgram(flowDataIPv4)) {
      RecordExtOSQUERY *record = new RecordExtOSQUERY(manager->getRecord());
      rec.addExtension(record);

      numberOfSuccessfullyRequests++;
   }

   return 0;
}

void OSQUERYPlugin::finish()
{
   delete manager;

   if (print_stats) {
      cout << "OSQUERY plugin stats:" << endl;
      cout << "Number of successfully processed requests: " << numberOfSuccessfullyRequests << endl;
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

ConvertedFlowData::ConvertedFlowData(uint32_t sourceIPv4, uint32_t destinationIPv4, uint16_t sourcePort,
  uint16_t destinationPort)
{
   convertIPv4(sourceIPv4, true);
   convertIPv4(destinationIPv4, false);
   convertPort(sourcePort, true);
   convertPort(destinationPort, false);
}

ConvertedFlowData::ConvertedFlowData(const uint8_t *sourceIPv6, const uint8_t *destinationIPv6, uint16_t sourcePort,
  uint16_t destinationPort)
{
   convertIPv6(sourceIPv6, true);
   convertIPv6(destinationIPv6, false);
   convertPort(sourcePort, true);
   convertPort(destinationPort, false);
}

void ConvertedFlowData::convertIPv4(uint32_t addr, bool isSourceIP)
{
   stringstream ss;

   ss << ((addr) & 0x000000ff) << "."
      << ((addr >> 8) & 0x000000ff) << "."
      << ((addr >> 16) & 0x000000ff) << "."
      << ((addr >> 24) & 0x000000ff);

   if (isSourceIP) {
      this->src_ip = ss.str();
   } else {
      this->dst_ip = ss.str();
   }
}

void ConvertedFlowData::convertIPv6(const uint8_t *addr, bool isSourceIP)
{
   stringstream ss;

   ss << HEX(addr[0]);
   for (int i = 1; i < 16; i++) {
      ss << ":" << HEX(addr[i]);
   }

   if (isSourceIP) {
      this->src_ip = ss.str();
   } else {
      this->dst_ip = ss.str();
   }
}

void ConvertedFlowData::convertPort(uint16_t port, bool isSourcePort)
{
   stringstream ss;

   ss << port;

   if (isSourcePort) {
      this->src_port = ss.str();
   } else {
      this->dst_port = ss.str();
   }
}

OsqueryRequestManager::OsqueryRequestManager() :
   inputFD(0),
   outputFD(0),
   buffer(NULL),
   pfd(NULL),
   recOsquery(NULL),
   isFDOpened(false),
   numberOfAttempts(0),
   osqueryProcessId(-1)
{
   buffer = new char [BUFFER_SIZE];

   pfd         = new pollfd;
   pfd->events = POLLIN;

   recOsquery = new RecordExtOSQUERY();

   while (true) {
      openOsqueryFD();
      if (handler.isFatalError()) {
         break;
      } else if (handler.isOpenFDError()) {
         continue;
      } else {
         break;
      }
   }
}

OsqueryRequestManager::~OsqueryRequestManager()
{
   delete[] buffer;
   delete pfd;
   delete recOsquery;
   closeOsqueryFD();
}

void OsqueryRequestManager::readInfoAboutOS()
{
   const string query =
     "SELECT ov.name, ov.major, ov.minor, ov.build, ov.platform, ov.platform_like, ov.arch, ki.version, si.hostname FROM os_version AS ov, kernel_info AS ki, system_info AS si;\r\n";

   if (executeQuery(query) > 0) {
      parseJsonOSVersion();
   }
}

bool OsqueryRequestManager::readInfoAboutProgram(const ConvertedFlowData &flowData)
{
   if (handler.isFatalError()) {
      return false;
   }

   recOsquery->program_name = DEFAULT_FILL_TEXT;
   recOsquery->username     = DEFAULT_FILL_TEXT;

   string pid;

   if (!getPID(pid, flowData)) {
      return false;
   }

   string query = "SELECT p.name, u.username FROM processes AS p INNER JOIN users AS u ON p.uid=u.uid "
     "WHERE p.pid='" + pid + "';\r\n";

   if (executeQuery(query) > 0) {
      if (parseJsonAboutProgram()) {
         return true;
      }
   }
   return false;
}

size_t OsqueryRequestManager::executeQuery(const string &query, bool reopenFD)
{
   if (reopenFD) {
      openOsqueryFD();
   }

   if (handler.isFatalError()) {
      return 0;
   }

   if (handler.isOpenFDError()) {
      return executeQuery(query, true);
   }

   handler.refresh();

   if (!writeToOsquery(query.c_str())) {
      return executeQuery(query, true);
   }

   size_t ret = readFromOsquery();

   if (handler.isReadError()) {
      return executeQuery(query, true);
   }

   if (handler.isReadSuccess()) {
      numberOfAttempts = 0;
      return ret;
   }

   return 0;
}

bool OsqueryRequestManager::writeToOsquery(const char *query)
{
   // If expression is true, a logical error has occurred.
   // There should be no logged errors when executing this method
   if (handler.isErrorState()) {
      handler.setFatalError();
      return false;
   }

   ssize_t length = strlen(query);
   ssize_t n      = write(inputFD, query, length);

   return (n != -1 && n == length);
}

size_t OsqueryRequestManager::readFromOsquery()
{
   // If expression is true, a logical error has occurred.
   // There should be no logged errors when executing this method
   if (handler.isErrorState()) {
      handler.setFatalError();
      return 0;
   }

   clearBuffer();
   pfd->revents = 0;

   int ret = poll(pfd, 1, POLL_TIMEOUT);

   // ret == -1 -> poll error.
   // ret == 0 -> poll timeout (osquery in json mode always returns at least empty json string("[\n\n]\n"),
   // if no response has been received, this is considered an error).
   if (ret == -1 || ret == 0) {
      handler.setReadError();
      return 0;
   }

   if (pfd->revents & POLLIN) {
      size_t bytesRead = 0;
      while (true) {
         if (bytesRead + READ_SIZE < BUFFER_SIZE) {
            ssize_t n = read(outputFD, buffer + bytesRead, READ_SIZE);

            // read error
            if (n < 0) {
               handler.setReadError();
               return 0;
            }

            bytesRead += n;

            // Error: less than 5 bytes were read
            if (bytesRead < 5) {
               clearBuffer();
               handler.setReadError();
               return 0;
            }

            if (n < READ_SIZE || buffer[bytesRead - 2] == ']') {
               buffer[bytesRead] = 0;
               handler.setReadSuccess();
               return bytesRead;
            }
         } else {
            ssize_t n = read(outputFD, buffer, READ_SIZE);

            // read error
            if (n < 0) {
               handler.setReadError();
               return 0;
            }

            if (n < READ_SIZE || buffer[n - 2] == ']') {
               clearBuffer();
               handler.setReadSuccess();
               return 0;
            }
         }
      }
   }
   handler.setReadError();
   return 0;
} // OsqueryRequestManager::readFromOsquery

void OsqueryRequestManager::openOsqueryFD()
{
   if (handler.isFatalError()) {
      return;
   }

   // All attempts have been exhausted
   if (numberOfAttempts >= MAX_NUMBER_OF_ATTEMPTS) {
      handler.setFatalError();
      return;
   }

   closeOsqueryFD();
   killPreviousProcesses();
   handler.reset();
   numberOfAttempts++;

   osqueryProcessId = popen2("osqueryi --json 2>/dev/null", &inputFD, &outputFD);

   if (osqueryProcessId <= 0) {
      handler.setOpenFDError();
      return;
   } else {
      isFDOpened = true;
      pfd->fd    = outputFD;
      return;
   }
}

void OsqueryRequestManager::closeOsqueryFD()
{
   if (isFDOpened) {
      close(inputFD);
      close(outputFD);
      isFDOpened = false;
   }
}

void OsqueryRequestManager::killPreviousProcesses(bool useWhonangOption) const
{
   if (useWhonangOption) {
      waitpid(-1, NULL, WNOHANG);
   } else {
      if (osqueryProcessId > 0) {
         waitpid(osqueryProcessId, NULL, 0);
      }
   }
}

bool OsqueryRequestManager::getPID(string &pid, const ConvertedFlowData &flowData)
{
   string query = "SELECT pid FROM process_open_sockets WHERE "
     "(local_address='" + flowData.src_ip + "' AND "
     "remote_address='" + flowData.dst_ip + "' AND "
     "local_port='" + flowData.src_port + "' AND "
     "remote_port='" + flowData.dst_port + "') OR "
     "(local_address='" + flowData.dst_ip + "' AND "
     "remote_address='" + flowData.src_ip + "' AND "
     "local_port='" + flowData.dst_port + "' AND "
     "remote_port='" + flowData.src_port + "') LIMIT 1;\r\n";

   if (executeQuery(query) > 0) {
      if (parseJsonSingleItem("pid", pid)) {
         return true;
      }
   }

   return false;
}

bool OsqueryRequestManager::parseJsonSingleItem(const string &singleKey, string &singleValue)
{
   int pos = getPositionForParseJson();

   if (pos == -1) {
      return false;
   }

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
         return count == 1;
      }

      if (key == singleKey) {
         singleValue = value;
         count++;
      } else {
         return false;
      }
   }
}

bool OsqueryRequestManager::parseJsonOSVersion()
{
   int pos = getPositionForParseJson();

   if (pos == -1) {
      return false;
   }

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
         recOsquery->os_arch = string(value);
         count++;
      } else if (key == "build") {
         recOsquery->os_build = value;
         count++;
      } else if (key == "hostname") {
         recOsquery->system_hostname = value;
         count++;
      } else if (key == "major") {
         recOsquery->os_major = atoi(value.c_str());
         count++;
      } else if (key == "minor") {
         recOsquery->os_minor = atoi(value.c_str());
         count++;
      } else if (key == "name") {
         recOsquery->os_name = value;
         count++;
      } else if (key == "platform") {
         recOsquery->os_platform = value;
         count++;
      } else if (key == "platform_like") {
         recOsquery->os_platform_like = value;
         count++;
      } else if (key == "version") {
         recOsquery->kernel_version = value;
         count++;
      } else {
         return false;
      }
   }
} // OsqueryRequestManager::parseJsonOSVersion

bool OsqueryRequestManager::parseJsonAboutProgram()
{
   int pos = getPositionForParseJson();

   if (pos == -1) {
      return false;
   }

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
         recOsquery->program_name = value;
         count++;
      } else if (key == "username") {
         recOsquery->username = value;
         count++;
      } else {
         return false;
      }
   }
}

int OsqueryRequestManager::parseJsonItem(int from, string &key, string &value)
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

int OsqueryRequestManager::parseString(int from, string &str)
{
   int pos         = from;
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

pid_t OsqueryRequestManager::popen2(const char *command, int *inFD, int *outFD) const
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
      close(p_stdin[WRITE_FD]);
      dup2(p_stdin[READ_FD], READ_FD);
      close(p_stdout[READ_FD]);
      dup2(p_stdout[WRITE_FD], WRITE_FD);
      execl("/bin/sh", "sh", "-c", command, NULL);
      perror("execl");
      exit(1);
   }

   inFD == NULL ? close(p_stdin[WRITE_FD]) : *inFD   = p_stdin[WRITE_FD];
   outFD == NULL ? close(p_stdout[READ_FD]) : *outFD = p_stdout[READ_FD];

   return pid;
}

int OsqueryRequestManager::getPositionForParseJson()
{
   int position = 0;

   while (buffer[position] != 0) {
      if (buffer[position] == '[') {
         return position + 1;
      }
      position++;
   }
   return -1;
}
