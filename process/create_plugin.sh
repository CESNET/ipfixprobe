#!/bin/bash

echo "Enter new plugin name (will be converted to lowercase): "
read PLUGIN

echo "Enter your name and email address (format: NAME SURNAME <EMAIL-ADDRESS>): "
read AUTHOR

PLUGIN="$(tr '[:upper:]' '[:lower:]' <<<"$PLUGIN")"
PLUGIN_UPPER="$(tr '[:lower:]' '[:upper:]' <<<"$PLUGIN")"

# Usage: print_basic_info <FILE-EXTENSION>
print_basic_info() {
   echo "/**
 * \\file ${PLUGIN}.${1}
 * \\brief Plugin for parsing ${PLUGIN} traffic.
 * \\author ${AUTHOR}
 * \\date $(date +%Y)
 */"
}

print_license() {
   echo "/*
 * Copyright (C) $(date +%Y) CESNET
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
"
}

print_hpp_code() {
   echo "#ifndef IPXP_PROCESS_${PLUGIN_UPPER}_HPP
#define IPXP_PROCESS_${PLUGIN_UPPER}_HPP

#include <cstring>

#ifdef WITH_NEMEA
  #include \"fields.h\"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define ${PLUGIN_UPPER}_UNIREC_TEMPLATE \"\" /* TODO: unirec template */

UR_FIELDS (
   /* TODO: unirec fields definition */
)

/**
 * \\brief Flow record extension header for storing parsed ${PLUGIN_UPPER} data.
 */
struct RecordExt${PLUGIN_UPPER} : public RecordExt {
   static int REGISTERED_ID;

   RecordExt${PLUGIN_UPPER}() : RecordExt(REGISTERED_ID)
   {
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
   }

   const char *get_unirec_tmplt() const
   {
      return ${PLUGIN_UPPER}_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      return 0;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_${PLUGIN_UPPER}_TEMPLATE(IPFIX_FIELD_NAMES)
         NULL
      };
      return ipfix_template;
   }
};

/**
 * \\brief Process plugin for parsing ${PLUGIN_UPPER} packets.
 */
class ${PLUGIN_UPPER}Plugin : public ProcessPlugin
{
public:
   ${PLUGIN_UPPER}Plugin();
   ~${PLUGIN_UPPER}Plugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser(\"${PLUGIN}\", \"Parse ${PLUGIN_UPPER} traffic\"); }
   std::string get_name() const { return \"${PLUGIN}\"; }
   RecordExt *get_ext() const { return new RecordExt${PLUGIN_UPPER}(); }
   ProcessPlugin *copy();

   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
};

}
#endif /* IPXP_PROCESS_${PLUGIN_UPPER}_HPP */
"
}

print_cpp_code() {
   echo "#include <iostream>

#include \"${PLUGIN}.hpp\"

namespace ipxp {

int RecordExt${PLUGIN_UPPER}::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord(\"${PLUGIN}\", [](){return new ${PLUGIN_UPPER}Plugin();});
   register_plugin(&rec);
   RecordExt${PLUGIN_UPPER}::REGISTERED_ID = register_extension();
}

${PLUGIN_UPPER}Plugin::${PLUGIN_UPPER}Plugin()
{
}

${PLUGIN_UPPER}Plugin::~${PLUGIN_UPPER}Plugin()
{
}

void ${PLUGIN_UPPER}Plugin::init(const char *params)
{
}

void ${PLUGIN_UPPER}Plugin::close()
{
}

ProcessPlugin *${PLUGIN_UPPER}Plugin::copy()
{
   return new ${PLUGIN_UPPER}Plugin(*this);
}

int ${PLUGIN_UPPER}Plugin::pre_create(Packet &pkt)
{
   return 0;
}

int ${PLUGIN_UPPER}Plugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int ${PLUGIN_UPPER}Plugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int ${PLUGIN_UPPER}Plugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void ${PLUGIN_UPPER}Plugin::pre_export(Flow &rec)
{
}

}
"
}

print_todo() {
   echo "Generated ${PLUGIN}.cpp and ${PLUGIN}.hpp files"
   echo
   echo "TODO:"
   echo "1) Add '${PLUGIN}.hpp' and '${PLUGIN}.cpp' files to ipfixprobe_process_src variable in Makefile.am"
   echo "2) Do the main work in ${PLUGIN}.cpp and ${PLUGIN}.hpp files - implement pre_create, post_create, pre_update, post_update and pre_export functions (also read and understand when these functions are called, info in ipfixprobe/process.hpp file)"
   echo "3.1) Add unirec fields to the UR_FIELDS and ${PLUGIN_UPPER}_UNIREC_TEMPLATE macro in ${PLUGIN}.hpp"
   echo "3.2) Add IPFIX template macro 'IPFIX_${PLUGIN_UPPER}_TEMPLATE' to ipfixprobe/ipfix-elements.hpp"
   echo "3.3) Define IPFIX fields"
   echo "3.4) Write function 'fill_ipfix' in ${PLUGIN}.hpp to fill fields to IPFIX message"
   echo "3.5) Write function 'fill_unirec' in ${PLUGIN}.hpp to fill fields to UNIREC message"
   echo "4) Update README.md"
   echo "5) Be happy with your new awesome ${PLUGIN} plugin!"
   echo
   echo "Optional work:"
   echo "1) Add pcap traffic sample for ${PLUGIN} plugin to pcaps directory"
   echo "2) Add test for ${PLUGIN} to tests directory"
   echo
   echo "NOTE: If you didn't modify pre_create, post_create, pre_update, post_update, pre_export functions, please remove them from ${PLUGIN}.cpp and ${PLUGIN}.hpp"
}

create_hpp_file() {
   FILE="${PLUGIN}.hpp"

   echo "Creating ${FILE} file..."
   print_basic_info hpp >"${FILE}"
   print_license        >>"${FILE}"
   print_hpp_code       >>"${FILE}"
}

create_cpp_file() {
   FILE="${PLUGIN}.cpp"

   echo "Creating ${FILE} file..."
   print_basic_info cpp >"${FILE}"
   print_license        >>"${FILE}"
   print_cpp_code       >>"${FILE}"
}

create_hpp_file
create_cpp_file
echo
print_todo
