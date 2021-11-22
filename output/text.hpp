/**
 * \file text.hpp
 * \brief Prints exported fields
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

#ifndef IPXP_OUTPUT_TEXT_HPP
#define IPXP_OUTPUT_TEXT_HPP

#include <config.h>

#include <string>

#include <ipfixprobe/output.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/utils.hpp>
#include <ipfixprobe/options.hpp>

namespace ipxp {

class TextOptParser : public OptionsParser
{
public:
   std::string m_file;
   bool m_to_file;
   bool m_hide_mac;

   TextOptParser() : OptionsParser("text", "Output plugin for text export"),
      m_file(""), m_to_file(false), m_hide_mac(false)
   {
      register_option("f", "file", "PATH", "Print output to file",
         [this](const char *arg){m_file = arg; m_to_file = true; return true;}, OptionFlags::RequiredArgument);
      register_option("m", "mac", "", "Hide mac addresses",
         [this](const char *arg){m_hide_mac = true; return true;}, OptionFlags::NoArgument);
   }
};

class TextExporter : public OutputPlugin
{
public:
   TextExporter();
   ~TextExporter();
   void init(const char *params);
   void init(const char *params, Plugins &plugins);
   void close();
   OptionsParser *get_parser() const { return new TextOptParser(); }
   std::string get_name() const { return "text"; }
   int export_flow(const Flow &flow);

private:
   std::ostream *m_out;
   bool m_hide_mac;

   void print_basic_flow(const Flow &flow);
};

}
#endif /* IPXP_OUTPUT_TEXT_HPP */
