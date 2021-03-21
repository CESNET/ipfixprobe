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
#include <cstring>
#include <cstdio>

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
   numberOfQueries = 0;
   manager = new OsqueryRequestManager();
   manager->readInfoAboutOS();
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
                  "remote_port='" + sdst_port + "' LIMIT 1);\r\n";

   manager->readInfoAboutProgram(query);

   RecordExtOSQUERY *record = new RecordExtOSQUERY(manager->getRecord());
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
   delete manager;

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

OsqueryRequestManager::OsqueryRequestManager() : inputFD(0),
                                                 outputFD(0),
                                                 buffer(NULL),
                                                 pfd(NULL),
                                                 recOsquery(NULL),
                                                 isFDOpened(false),
                                                 numberOfAttempts(0),
                                                 osqueryProcessId(-1)
{
    pfd = new pollfd;
    pfd->events = POLLIN;

    recOsquery = new RecordExtOSQUERY();

    while (true) {
        openOsqueryFD();
        if (handler.getFatalErrorFlag()) {
            break;
        } else if (handler.getOpenFDErrorFlag()) {
            continue;
        } else {
            buffer = new char [BUFFER_SIZE];
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
    const string query = "SELECT ov.name, ov.major, ov.minor, ov.build, ov.platform, ov.platform_like, ov.arch, ki.version, si.hostname FROM os_version AS ov, kernel_info AS ki, system_info AS si;\r\n";
    if (executeQuery(query) > 0) {
        parseJsonOSVersion();
    }
}

void OsqueryRequestManager::readInfoAboutProgram(const string &query)
{
    recOsquery->program_name = DEFAULT_FILL_TEXT;
    recOsquery->username = DEFAULT_FILL_TEXT;

    if (executeQuery(query) > 0) {
        parseJsonAboutProgram();
    }
}

size_t OsqueryRequestManager::executeQuery(const string &query, bool reopenFD)
{
    if (reopenFD) {
        openOsqueryFD();
    }

    if (handler.getFatalErrorFlag()) {
        return 0;
    }

    if (handler.getOpenFDErrorFlag()) {
        return executeQuery(query, true);
    }

    handler.refresh();

    if (!writeToOsquery(query.c_str())) {
        return executeQuery(query, true);
    }

    size_t ret = readFromOsquery();

    if (handler.getReadErrorFlag()) {
        return executeQuery(query, true);
    }

    if (handler.getReadSuccessFlag()) {
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
        handler.setFatalErrorFlag();
        return false;
    }

    ssize_t length = strlen(query);
    ssize_t n = write(inputFD, query, length);

    return (n != -1 && n == length);
}

size_t OsqueryRequestManager::readFromOsquery()
{
    // If expression is true, a logical error has occurred.
    // There should be no logged errors when executing this method
    if (handler.isErrorState()) {
        handler.setFatalErrorFlag();
        return 0;
    }

    clearBuffer();
    pfd->revents = 0;

    int ret = poll(pfd, 1, POLL_TIMEOUT);

    // ret == -1 -> poll error.
    // ret == 0 -> poll timeout (osquery in json mode always returns at least empty json string("[\n\n]\n"),
    // if no response has been received, this is considered an error).
    if (ret == -1 || ret == 0) {
        handler.setReadErrorFlag();
        return 0;
    }

    if (pfd->revents & POLLIN) {
        size_t bytesRead = 0;
        while (true) {
            if (bytesRead + READ_SIZE < BUFFER_SIZE) {
                ssize_t n = read(outputFD, buffer + bytesRead, READ_SIZE);

                // read error
                if (n < 0) {
                    handler.setReadErrorFlag();
                    return 0;
                }

                bytesRead += n;

                // Error: less than 5 bytes were read
                if (bytesRead < 5) {
                    clearBuffer();
                    handler.setReadErrorFlag();
                    return 0;
                }

                if (n < READ_SIZE || buffer[bytesRead - 2] == ']') {
                    buffer[bytesRead] = 0;
                    handler.setReadSuccessFlag();
                    return bytesRead;
                }
            } else {
                ssize_t n = read(outputFD, buffer, READ_SIZE);

                // read error
                if (n < 0) {
                    handler.setReadErrorFlag();
                    return 0;
                }

                if (n < READ_SIZE || buffer[n - 2] == ']') {
                    clearBuffer();
                    handler.setReadSuccessFlag();
                    return 0;
                }
            }

        }
    }
    handler.setReadErrorFlag();
    return 0;
}

void OsqueryRequestManager::openOsqueryFD()
{
    if (handler.getFatalErrorFlag()) {
        return;
    }

    // All attempts have been exhausted
    if (numberOfAttempts >= MAX_NUMBER_OF_ATTEMPTS) {
        handler.setFatalErrorFlag();
        return;
    }

    closeOsqueryFD();
    killPreviousProcesses();
    handler.reset();
    numberOfAttempts++;

    osqueryProcessId = popen2("osqueryi --json", &inputFD, &outputFD);

    if (osqueryProcessId <= 0) {
        handler.setOpenFDErrorFlag();
        return;
    } else {
        isFDOpened = true;
        pfd->fd = outputFD;
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

bool OsqueryRequestManager::parseJsonOSVersion()
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
}

bool OsqueryRequestManager::parseJsonAboutProgram()
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

    inFD == NULL ? close(p_stdin[WRITE_FD]) : *inFD = p_stdin[WRITE_FD];
    outFD == NULL ? close(p_stdout[READ_FD]) : *outFD = p_stdout[READ_FD];

    return pid;
}