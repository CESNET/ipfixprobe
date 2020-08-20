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
 * \\file ${PLUGIN}plugin.${1}
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

print_h_code() {
   echo "#ifndef ${PLUGIN_UPPER}PLUGIN_H
#define ${PLUGIN_UPPER}PLUGIN_H

#include <string>

#include \"fields.h\"
#include \"flowifc.h\"
#include \"flowcacheplugin.h\"
#include \"packet.h\"
#include \"flow_meter.h\"

using namespace std;

/**
 * \\brief Flow record extension header for storing parsed ${PLUGIN_UPPER} packets.
 */
struct RecordExt${PLUGIN_UPPER} : RecordExt {

   RecordExt${PLUGIN_UPPER}() : RecordExt(${PLUGIN})
   {
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      return 0;
   }
};

/**
 * \\brief Flow cache plugin for parsing ${PLUGIN_UPPER} packets.
 */
class ${PLUGIN_UPPER}Plugin : public FlowCachePlugin
{
public:
   ${PLUGIN_UPPER}Plugin(const options_t &module_options);
   ${PLUGIN_UPPER}Plugin(const options_t &module_options, vector<plugin_opt> plugin_options);
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
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif
"
}

print_cpp_code() {
   echo "#include <iostream>

#include \"${PLUGIN}plugin.h\"
#include \"flowifc.h\"
#include \"flowcacheplugin.h\"
#include \"packet.h\"
#include \"flow_meter.h\"
#include \"ipfix-elements.h\"

using namespace std;

#define ${PLUGIN_UPPER}_UNIREC_TEMPLATE \"\" /* TODO: unirec template */

UR_FIELDS (
   /* TODO: unirec fields definition */
)

${PLUGIN_UPPER}Plugin::${PLUGIN_UPPER}Plugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

${PLUGIN_UPPER}Plugin::${PLUGIN_UPPER}Plugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
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

void ${PLUGIN_UPPER}Plugin::finish()
{
   if (print_stats) {
      //cout << \"${PLUGIN_UPPER} plugin stats:\" << endl;
   }
}

const char *ipfix_${PLUGIN_LOWER}_template[] = {
   IPFIX_${PLUGIN_UPPER}_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **${PLUGIN_UPPER}Plugin::get_ipfix_string()
{
   return ipfix_${PLUGIN_LOWER}_template;
}

string ${PLUGIN_UPPER}Plugin::get_unirec_field_string()
{
   return ${PLUGIN_UPPER}_UNIREC_TEMPLATE;
}

bool ${PLUGIN_UPPER}Plugin::include_basic_flow_fields()
{
   return true;
}
"
}

print_todo() {
   echo "Generated ${PLUGIN_LOWER}plugin.cpp and ${PLUGIN_LOWER}plugin.h files"
   echo
   echo "TODO:"
   echo "1) Add '${PLUGIN}plugin.h' and '${PLUGIN}plugin.cpp' files to flow_meter_src variable in Makefile.am"
   echo "2) Add '${PLUGIN}' entry to the extTypeEnum in flowifc.h"
   echo "3) Add '#include <${PLUGIN}plugin.h>' line to flow_meter.cpp"
   echo "4) Add ${PLUGIN} to list of supported plugins for -p param in flow_meter.cpp - SUPPORTED_PLUGINS_LIST macro (also update README.md)"
   echo "5) Add plugin support in parse_plugin_settings function in flow_meter.cpp"
   echo "6.1) Add unirec fields to the UR_FIELDS and ${PLUGIN_UPPER}_UNIREC_TEMPLATE macro in ${PLUGIN}plugin.cpp"
   echo "6.2) Add IPFIX template macro 'IPFIX_${PLUGIN_UPPER}_TEMPLATE' to ipfix-elements.h"
   echo "6.3) Define IPFIX fields"
   echo "6.4) Write function 'fillIPFIX' in ${PLUGIN_LOWER}plugin.h to fill fields to IPFIX message"
   echo "7) Do the final work in ${PLUGIN}plugin.cpp and ${PLUGIN}plugin.h files - implement pre_create, post_create, pre_update, post_update, pre_export, include_basic_flow_fields and fill_unirec functions (also read and understand when these functions are called, info in flowcacheplugin.h file)"
   echo "8) Be happy with your new awesome ${PLUGIN} plugin!"
   echo
   echo "Optional work:"
   echo "1) Add pcap traffic sample for ${PLUGIN} plugin to traffic-samples directory"
   echo "2) Add test for ${PLUGIN} to tests directory"
   echo
   echo "NOTE: If you didn't modify pre_create, post_create, pre_update, post_update, pre_export or include_basic_flow_fields functions, please remove them from ${PLUGIN}plugin.cpp and ${PLUGIN}plugin.h"
}

create_h_file() {
   FILE="${PLUGIN}plugin.h"

   echo "Creating ${FILE} file..."
   print_basic_info h   >"${FILE}"
   print_license        >>"${FILE}"
   print_h_code         >>"${FILE}"
}

create_cpp_file() {
   FILE="${PLUGIN}plugin.cpp"

   echo "Creating ${FILE} file..."
   print_basic_info cpp >"${FILE}"
   print_license        >>"${FILE}"
   print_cpp_code       >>"${FILE}"
}

create_h_file
create_cpp_file
echo
print_todo

