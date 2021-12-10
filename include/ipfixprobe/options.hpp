/**
 * \file options.hpp
 * \brief Options parser
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

#ifndef IPXP_OPTIONS_HPP
#define IPXP_OPTIONS_HPP

#include <vector>
#include <map>
#include <functional>
#include <stdexcept>
#include <string>
#include <iostream>

namespace ipxp {

class OptionsParser
{
public:
   static const char DELIM = ';';
   typedef std::function<bool(const char *opt)> OptionParserFunc;
   enum OptionFlags : uint32_t {
      RequiredArgument = 1,
      OptionalArgument = 2,
      NoArgument = 4
   };

   OptionsParser();
   OptionsParser(const std::string &name, const std::string &info);
   ~OptionsParser();
   OptionsParser(OptionsParser &p) = delete;
   OptionsParser(OptionsParser &&p) = delete;
   void operator=(OptionsParser &p) = delete;
   void operator=(OptionsParser &&p) = delete;
   void parse(const char *args) const;
   void parse(int argc, const char **argv) const;
   void usage(std::ostream &os, int indentation = 0, std::string mod_name = "") const;

protected:
   std::string m_name;
   std::string m_info;
   char m_delim;
   struct Option {
      std::string m_short;
      std::string m_long;
      std::string m_hint;
      std::string m_description;
      OptionParserFunc m_parser;
      OptionFlags m_flags;
   };
   std::vector<Option *> m_options;
   std::map<std::string, Option *> m_long;
   std::map<std::string, Option *> m_short;

   void register_option(std::string arg_short, std::string arg_long, std::string arg_hint, std::string description, OptionParserFunc parser, OptionFlags flags=OptionFlags::RequiredArgument);
};

class ParserError : public std::runtime_error
{
public:
   explicit ParserError(const std::string &msg) : std::runtime_error(msg) {};
   explicit ParserError(const char *msg) : std::runtime_error(msg) {};
};

}
#endif /* IPXP_OPTIONS_HPP */
