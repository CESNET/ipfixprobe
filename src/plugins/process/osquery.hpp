/**
 * \file osqueryplugin.hpp
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
 *
 *
 */

#ifndef IPXP_PROCESS_OSQUERY_HPP
#define IPXP_PROCESS_OSQUERY_HPP

#include <string>
#include <sstream>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>

#ifdef WITH_NEMEA
# include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

#define DEFAULT_FILL_TEXT "UNDEFINED"

// OsqueryStateHandler
#define FATAL_ERROR   0b00000001 // 1;  Fatal error, cannot be fixed
#define OPEN_FD_ERROR 0b00000010 // 2;  Failed to open osquery FD
#define READ_ERROR    0b00000100 // 4;  Error while reading
#define READ_SUCCESS  0b00001000 // 8;  Data read successfully

// OsqueryRequestManager
#define BUFFER_SIZE            1024 * 20 + 1
#define READ_SIZE              1024
#define POLL_TIMEOUT           200 // millis
#define READ_FD                0
#define WRITE_FD               1
#define MAX_NUMBER_OF_ATTEMPTS 2 // Max number of osquery error correction attempts

#define OSQUERY_UNIREC_TEMPLATE \
   "OSQUERY_PROGRAM_NAME,OSQUERY_USERNAME,OSQUERY_OS_NAME,OSQUERY_OS_MAJOR,OSQUERY_OS_MINOR,OSQUERY_OS_BUILD,OSQUERY_OS_PLATFORM,OSQUERY_OS_PLATFORM_LIKE,OSQUERY_OS_ARCH,OSQUERY_KERNEL_VERSION,OSQUERY_SYSTEM_HOSTNAME"

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

namespace ipxp {

/**
 * \brief Flow record extension header for storing parsed OSQUERY packets.
 */
struct RecordExtOSQUERY : public RecordExt {
   static int REGISTERED_ID;
   std::string   program_name;
   std::string   username;
   std::string   os_name;
   uint16_t os_major;
   uint16_t os_minor;
   std::string   os_build;
   std::string   os_platform;
   std::string   os_platform_like;
   std::string   os_arch;
   std::string   kernel_version;
   std::string   system_hostname;


   RecordExtOSQUERY() : RecordExt(REGISTERED_ID)
   {
      program_name     = DEFAULT_FILL_TEXT;
      username         = DEFAULT_FILL_TEXT;
      os_name          = DEFAULT_FILL_TEXT;
      os_major         = 0;
      os_minor         = 0;
      os_build         = DEFAULT_FILL_TEXT;
      os_platform      = DEFAULT_FILL_TEXT;
      os_platform_like = DEFAULT_FILL_TEXT;
      os_arch          = DEFAULT_FILL_TEXT;
      kernel_version   = DEFAULT_FILL_TEXT;
      system_hostname  = DEFAULT_FILL_TEXT;
   }

   RecordExtOSQUERY(const RecordExtOSQUERY *record) : RecordExt(REGISTERED_ID)
   {
      program_name     = record->program_name;
      username         = record->username;
      os_name          = record->os_name;
      os_major         = record->os_major;
      os_minor         = record->os_minor;
      os_build         = record->os_build;
      os_platform      = record->os_platform;
      os_platform_like = record->os_platform_like;
      os_arch          = record->os_arch;
      kernel_version   = record->kernel_version;
      system_hostname  = record->system_hostname;
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

   const char *get_unirec_tmplt() const
   {
      return OSQUERY_UNIREC_TEMPLATE;
   }
   #endif // ifdef WITH_NEMEA

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
   } // fillIPFIX

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_OSQUERY_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };

      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "program=\"" << program_name << "\""
         << ",username=\"" << username << "\""
         << ",osname=\"" << os_name << "\""
         << ",major=" << os_major
         << ",minor=" << os_minor
         << ",build=\"" << os_build << "\""
         << ",platform=\"" << os_platform << "\""
         << ",arch=\"" << os_arch << "\""
         << ",kernel=\"" << kernel_version << "\""
         << ",hostname=\"" << system_hostname << "\"";
      return out.str();
   }
};


/**
 * \brief Additional structure for handling osquery states.
 */
struct OsqueryStateHandler {
   OsqueryStateHandler() : OSQUERY_STATE(0){ }

   bool isErrorState() const { return (OSQUERY_STATE & (FATAL_ERROR | OPEN_FD_ERROR | READ_ERROR)); }

   void setFatalError(){ OSQUERY_STATE |= FATAL_ERROR; }

   bool isFatalError() const { return (OSQUERY_STATE & FATAL_ERROR); }

   void setOpenFDError(){ OSQUERY_STATE |= OPEN_FD_ERROR; }

   bool isOpenFDError() const { return (OSQUERY_STATE & OPEN_FD_ERROR); }

   void setReadError(){ OSQUERY_STATE |= READ_ERROR; }

   bool isReadError() const { return (OSQUERY_STATE & READ_ERROR); }

   void setReadSuccess(){ OSQUERY_STATE |= READ_SUCCESS; }

   bool isReadSuccess() const { return (OSQUERY_STATE & READ_SUCCESS); }

   /**
    * Reset the \p OSQUERY_STATE. Fatal and open fd errors will not be reset.
    */
   void refresh(){ OSQUERY_STATE = OSQUERY_STATE & (FATAL_ERROR | OPEN_FD_ERROR); }

   /**
    * Reset the \p OSQUERY_STATE. Fatal and open fd errors will be reset.
    */
   void reset(){ OSQUERY_STATE = 0; }

private:
   uint8_t OSQUERY_STATE;
};


/**
 * \brief Additional structure for store and convert data from flow (src_ip, dst_ip, src_port, dst_port) to string.
 */
struct ConvertedFlowData {
   /**
    * Constructor for IPv4-based flow.
    * @param sourceIPv4 source IPv4 address.
    * @param destinationIPv4 destination IPv4 address.
    * @param sourcePort source port.
    * @param destinationPort destination port.
    */
   ConvertedFlowData(uint32_t sourceIPv4, uint32_t destinationIPv4, uint16_t sourcePort, uint16_t destinationPort);

   /**
    * Constructor for IPv6-based flow.
    * @param sourceIPv6 source IPv6 address.
    * @param destinationIPv6 destination IPv6 address.
    * @param sourcePort source port.
    * @param destinationPort destination port.
    */
   ConvertedFlowData(const uint8_t *sourceIPv6, const uint8_t *destinationIPv6, uint16_t sourcePort,
     uint16_t destinationPort);

   std::string src_ip;
   std::string dst_ip;
   std::string src_port;
   std::string dst_port;

private:

   /**
    * Converts an IPv4 numeric value to a string.
    * @param addr IPv4 address.
    * @param isSourceIP if true - source IP conversion mode, if false - destination IP conversion mode.
    */
   void convertIPv4(uint32_t addr, bool isSourceIP);

   /**
    * Converts an IPv6 numeric value to a string.
    * @param addr IPv6 address.
    * @param isSourceIP if true - source IP conversion mode, if false - destination IP conversion mode.
    */
   void convertIPv6(const uint8_t *addr, bool isSourceIP);

   /**
    * Converts the numeric port value to a string.
    * @param port
    * @param isSourcePort if true - source port conversion mode, if false - destination port conversion mode.
    */
   void convertPort(uint16_t port, bool isSourcePort);
};


/**
 * \brief Manager for communication with osquery
 */
struct OsqueryRequestManager {
   OsqueryRequestManager();

   ~OsqueryRequestManager();

   const RecordExtOSQUERY *getRecord(){ return recOsquery; }

   /**
    * Fills the record with OS values from osquery.
    */
   void readInfoAboutOS();

   /**
    * Fills the record with program values from osquery.
    * @param flowData flow data converted to string.
    * @return true if success or false.
    */
   bool readInfoAboutProgram(const ConvertedFlowData &flowData);

private:

   /**
    * Sends a request and receives a response from osquery.
    * @param query sql query according to osquery standards.
    * @param reopenFD if true - tries to reopen fd.
    * @return number of bytes read.
    */
   size_t executeQuery(const std::string &query, bool reopenFD = false);

   /**
    * Writes query to osquery input FD.
    * @param query sql query according to osquery standards.
    * @return true if success or false.
    */
   bool writeToOsquery(const char *query);

   /**
    * Reads data from osquery output FD.
    * \note Can change osquery state. Possible changes: READ_ERROR, READ_SUCCESS.
    * @return number of bytes read.
    */
   size_t readFromOsquery();

   /**
    * Opens osquery FD.
    * \note Can change osquery state. Possible changes: FATAL_ERROR, OPEN_FD_ERROR.
    */
   void openOsqueryFD();

   /**
    * Closes osquery FD.
    */
   void closeOsqueryFD();

   /**
    * Before reopening osquery tries to kill the previous osquery process.
    *
    * If \p useWhonangOption is true then the waitpid() function will be used
    * in non-blocking mode(can be called before the process is ready to close,
    * the process will remain in a zombie state). At the end of the application,
    * a zombie process may remain, it will be killed when the application is closed.
    * Else if \p useWhonangOption is false then the waitpid() function will be used
    * in blocking mode(will wait for the process to complete). Will kill all unnecessary
    * processes, but will block the application until the killed process is finished.
    *
    * @param useWhonangOption if true will be used non-blocking mode.
    */
   void killPreviousProcesses(bool useWhonangOption = true) const;

   /**
    * Tries to get the process id from table "process_open_sockets".
    * @param[out] pid      process id.
    * @param[in]  flowData flow data converted to string.
    * @return true true if success or false.
    */
   bool getPID(std::string &pid, const ConvertedFlowData &flowData);

   /**
    * Parses json string with only one element.
    * @param[in]  singleKey    key.
    * @param[out] singleValue  value.
    * @return true if success or false.
    */
   bool parseJsonSingleItem(const std::string &singleKey, std::string &singleValue);

   /**
    * Parses json by template.
    * @return true if success or false.
    */
   bool parseJsonOSVersion();

   /**
    * Parses json by template.
    * @return true if success or false.
    */
   bool parseJsonAboutProgram();

   /**
    * From position \p from tries to find two strings between quotes ["key":"value"].
    * @param[in]  from  start position in the buffer.
    * @param[out] key   value for the "key" parsing result.
    * @param[out] value value for the "value" parsing result.
    * @return the position where the text search ended, 0 if end of json row or -1 if end of buffer.
    */
   int parseJsonItem(int from, std::string &key, std::string &value);

   /**
    * From position \p from tries to find string between quotes.
    * @param[in]  from start position in the buffer.
    * @param[out] str  value for the parsing result.
    * @return the position where the text search ended, 0 if end of json row or -1 if end of buffer.
    */
   int parseString(int from, std::string &str);

   /**
    * Create a new process for connecting FD.
    * @param[in]  command  command to execute in sh.
    * @param[out] inFD     input FD.
    * @param[out] outFD    output FD.
    * @return pid of the new process.
    */
   pid_t popen2(const char *command, int *inFD, int *outFD) const;

   /**
    * Sets the first byte in the buffer to zero
    */
   void clearBuffer(){ buffer[0] = 0; }

   /**
    * Tries to find the position in the buffer where the json data starts.
    * @return position number or -1 if position was not found.
    */
   int getPositionForParseJson();

   int                 inputFD;
   int                 outputFD;
   char *              buffer;
   pollfd *            pfd;
   RecordExtOSQUERY *  recOsquery;
   bool                isFDOpened;
   int                 numberOfAttempts;
   pid_t               osqueryProcessId;

   OsqueryStateHandler handler;
};


/**
 * \brief Flow cache plugin for parsing OSQUERY packets.
 */
class OSQUERYPlugin : public ProcessPlugin
{
public:
   OSQUERYPlugin();
   ~OSQUERYPlugin();
   OSQUERYPlugin(const OSQUERYPlugin &p);
   void init(const char *params);
   void close();
   RecordExt *get_ext() const { return new RecordExtOSQUERY(); }
   OptionsParser *get_parser() const { return new OptionsParser("osquery", "Collect information about locally outbound flows from OS"); }
   std::string get_name() const { return "osquery"; }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   void finish(bool print_stats);

private:
   OsqueryRequestManager *manager;
   int numberOfSuccessfullyRequests;
};

}
#endif /* IPXP_PROCESS_OSQUERY_HPP */
