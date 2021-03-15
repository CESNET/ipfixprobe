/**
 * \file osqueryplugin.h
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

#ifndef OSQUERYPLUGIN_H
#define OSQUERYPLUGIN_H

#include <string>
#include <poll.h>
#include <unistd.h>


#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

using namespace std;

#define READ 0
#define WRITE 1
#define POLL_TIMEOUT 200 // in millis
#define OSQUERY_FIELD_LENGTH 64
#define BUFFER_SIZE 20 * 1024
#define READ_SIZE 1024
#define UNDEFINED_TEXT "UNDEFINED"

/**
 * \brief Flow record extension header for storing parsed OSQUERY packets.
 */
struct RecordExtOSQUERY : RecordExt {
    string program_name; // fill undefined value
    string username; // fill undefined value
    string os_name;
    uint16_t os_major;
    uint16_t os_minor;
    string os_build;
    string os_platform;
    string os_platform_like;
    string os_arch;
    string kernel_version;
    string system_hostname;


   RecordExtOSQUERY() : RecordExt(osquery)
   {
       program_name = UNDEFINED_TEXT;
       username = UNDEFINED_TEXT;
       os_name = UNDEFINED_TEXT;
       os_major = 0;
       os_minor = 0;
       os_build = UNDEFINED_TEXT;
       os_platform = UNDEFINED_TEXT;
       os_platform_like = UNDEFINED_TEXT;
       os_arch = UNDEFINED_TEXT;
       kernel_version = UNDEFINED_TEXT;
       system_hostname = UNDEFINED_TEXT;
   }

   RecordExtOSQUERY(const RecordExtOSQUERY *record) : RecordExt(osquery) {
       program_name = record->program_name;
       username = record->username;
       os_name = record->os_name;
       os_major = record->os_major;
       os_minor = record->os_minor;
       os_build = record->os_build;
       os_platform = record->os_platform;
       os_platform_like = record->os_platform_like;
       os_arch = record->os_arch;
       kernel_version = record->kernel_version;
       system_hostname = record->system_hostname;
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
       ur_set_string(tmplt, record, F_OSQUERY_PROGRAM_NAME, program_name.c_str());
       ur_set_string(tmplt, record, F_OSQUERY_USERNAME, username.c_str());
       ur_set_string(tmplt, record, F_OSQUERY_OS_NAME, os_name.c_str());
       ur_set(tmplt, record, F_OSQUERY_OS_MAJOR, os_major);
       ur_set(tmplt, record, F_OSQUERY_OS_MINOR, os_minor);
       ur_set_string(tmplt, record, F_OSQUERY_OS_BUILD, os_build.c_str());
       ur_set_string(tmplt, record, F_OSQUERY_OS_PLATFORM, os_platform.c_str());
       ur_set_string(tmplt, record, F_OSQUERY_OS_PLATFORM_LIKE, os_platform_like.c_str());
       ur_set_string(tmplt, record, F_OSQUERY_OS_ARCH, os_arch.c_str());
       ur_set_string(tmplt, record, F_OSQUERY_KERNEL_VERSION, kernel_version.c_str());
       ur_set_string(tmplt, record, F_OSQUERY_SYSTEM_HOSTNAME, system_hostname.c_str());
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
       int length, total_length = 0;

       // OSQUERY_PROGRAM_NAME
       length = program_name.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, program_name.c_str(), length);
       total_length += length + 1;

       // OSQUERY_USERNAME
       length = username.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, username.c_str(), length);
       total_length += length + 1;

       // OSQUERY_OS_NAME
       length = os_name.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, os_name.c_str(), length);
       total_length += length + 1;

       // OSQUERY_OS_MAJOR
       *(uint16_t *) (buffer + total_length) = ntohs(os_major);
       total_length += 2;

       // OSQUERY_OS_MINOR
       *(uint16_t *) (buffer + total_length) = ntohs(os_minor);
       total_length += 2;

       // OSQUERY_OS_BUILD
       length = os_build.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, os_build.c_str(), length);
       total_length += length + 1;

       // OSQUERY_OS_PLATFORM
       length = os_platform.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, os_platform.c_str(), length);
       total_length += length + 1;

       // OSQUERY_OS_PLATFORM_LIKE
       length = os_platform_like.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, os_platform_like.c_str(), length);
       total_length += length + 1;

       // OSQUERY_OS_ARCH
       length = os_arch.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, os_arch.c_str(), length);
       total_length += length + 1;

       // OSQUERY_KERNEL_VERSION
       length = kernel_version.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, kernel_version.c_str(), length);
       total_length += length + 1;

       // OSQUERY_SYSTEM_HOSTNAME
       length = system_hostname.length();
       if (total_length + length + 1 > size) {
           return -1;
       }
       buffer[total_length] = length;
       memcpy(buffer + total_length + 1, system_hostname.c_str(), length);
       total_length += length + 1;

       return total_length;
   }
};

/**
 * \brief Flow cache plugin for parsing OSQUERY packets.
 */
class OSQUERYPlugin : public FlowCachePlugin
{
public:
   OSQUERYPlugin(const options_t &module_options);
   OSQUERYPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   void init();
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   bool getResponse(const string &query);
   /**
    * Reads osquery data
    * @param query
    * @return void
    */
   void getResponseFromOsquery(const string &query);
   bool parseJsonOSVersion();
   bool parseJsonAboutProgram();

   /**
    * Parses a single json element "key":"value"
    * @param from position of the first character of the buffer
    * @param key
    * @param value
    * @return -1 - error, 0 - end of json row, other - position of next value
    */
   int parseJsonItem(int from, string &key, string &value);

   /**
    * Parses a single json string
    * @param from position of the first character of the buffer
    * @param str string from json
    * @return -1 - error, 0 - end of json row, other - position of next value
    */
   int parseString(int from, string &str);

   pid_t popen2(const char *command, int *inFD, int *outFD);

   char *buffer;
   pollfd *pollFDS;
   RecordExtOSQUERY* recordExtOsquery;
   int inputFD;
   int outputFD;
   bool osqueryFatalError;
   bool osqueryFail;
   int numberOfQueries;
   bool print_stats;       /**< Print stats when flow cache finish. */
};

#endif

