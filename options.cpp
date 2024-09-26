/**
 * \file options.cpp
 * \brief Options parser source
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

#include <vector>
#include <string>
#include <iomanip>

#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

OptionsParser::OptionsParser() : m_name(""), m_info(""), m_delim(OptionsParser::DELIM)
{
}

OptionsParser::OptionsParser(const std::string &name, const std::string &info) : m_name(name), m_info(info), m_delim(OptionsParser::DELIM)
{
}

OptionsParser::~OptionsParser()
{
   for (const auto &it : m_options) {
      delete it;
   }
   m_options.clear();
   m_short.clear();
   m_long.clear();
}

void OptionsParser::parse(const char *args) const
{
   std::vector<std::string> tokens;
   std::vector<const char *> token_ptrs;
   size_t first = 0;
   size_t last = 0;
   if (args == nullptr || args[0] == 0) {
      parse(0, nullptr);
      return;
   }
   while (1) {
      if (args[last] == m_delim || !args[last]) {
         std::string token = std::string(args, first, last - first);
         size_t pos = token.find("=");
         std::string name = token.substr(0, pos);
         std::string arg;

         tokens.push_back(name);
         if (pos != std::string::npos) {
            arg = token.substr(pos + 1, std::string::npos);
            tokens.push_back(arg);
         }
         first = last + 1;
      }
      if (!args[last]) {
         break;
      }
      last += 1;
   }
   for (const auto &it : tokens) {
      token_ptrs.push_back(it.c_str());
   }
   parse(token_ptrs.size(), token_ptrs.data());
}

void OptionsParser::parse(int argc, const char **argv) const
{
   if (argc && !argv) {
      throw std::runtime_error("invalid arguments passed");
   }
   for (int i = 0; i < argc; i++) {
      Option *opt_spec = nullptr;
      std::string opt = argv[i];
      std::string eq_param;
      const char *arg = nullptr;
      size_t eq_pos = opt.find("=");
      if (opt.empty()) {
         continue;
      }
      if (eq_pos != std::string::npos) {
         eq_param = opt.substr(eq_pos + 1);
         opt = opt.erase(eq_pos);
      }

      if (m_long.find(opt) != m_long.end()) {
         opt_spec = m_long.at(opt);
      } else if (m_short.find(opt) != m_short.end()) {
         opt_spec = m_short.at(opt);
      } else {
         throw ParserError("invalid option " + opt);
      }

      if (opt_spec->m_flags & OptionFlags::RequiredArgument) {
         if (eq_pos != std::string::npos) {
            arg = eq_param.c_str();
         } else {
            if (i + 1 == argc) {
               throw ParserError("missing argument for option " + opt);
            }
            arg = argv[i + 1];
            i++;
         }
      } else if (opt_spec->m_flags & OptionFlags::OptionalArgument) {
         if (eq_pos != std::string::npos) {
            arg = eq_param.c_str();
         } else {
            if (i + 1 < argc &&
               m_long.find(argv[i + 1]) == m_long.end() && m_short.find(argv[i + 1]) == m_short.end()) {
               arg = argv[i + 1];
               i++;
            }
         }
      }

      if (!opt_spec->m_parser(arg)) {
         throw ParserError("invalid argument for option " + opt);
      }
   }
}

void OptionsParser::register_option(std::string arg_short, std::string arg_long, std::string arg_hint, std::string description, OptionParserFunc parser, OptionsParser::OptionFlags flags)
{
   if (arg_short.empty() || arg_long.empty() || description.empty()) {
      throw std::runtime_error("invalid option registration: short, long or description string is missing");
   }

   if (m_short.find(arg_short) != m_short.end() ||
       m_long.find(arg_long) != m_long.end()) {
      throw std::runtime_error("invalid option registration: option " + arg_short + " " + arg_long + " already exists");
   }

   Option *opt = new Option();
   opt->m_short = arg_short;
   opt->m_long = arg_long;
   opt->m_hint = arg_hint;
   opt->m_description = description;
   opt->m_parser = parser;
   opt->m_flags = flags;

   m_options.push_back(opt);
   m_short[arg_short] = opt;
   m_long[arg_long] = opt;
}

void OptionsParser::usage(std::ostream &os, int indentation, std::string mod_name) const
{
   std::string indent_str = std::string(indentation, ' ');
   size_t max_long = 0;
   size_t max_short = 0;
   size_t max_req_arg = 0;
   for (const auto &it : m_options) {
      size_t arg_len = it->m_flags & OptionFlags::RequiredArgument ? it->m_hint.size() : 0;
      arg_len = it->m_flags & OptionFlags::OptionalArgument ? it->m_hint.size() + 2 : arg_len;

      max_short = max(max_short, it->m_short.size());
      max_long = max(max_long, it->m_long.size());
      max_req_arg = max(max_req_arg, arg_len);
   }

   std::string name = (mod_name.empty() ? m_name : mod_name);
   std::string usage_str = "Usage: ";
   os << indent_str << name  << std::endl;
   os << indent_str << m_info << std::endl;
   os << indent_str << usage_str << name;
   for (const auto &it : m_options) {
      std::string arg_str = it->m_flags & OptionFlags::RequiredArgument ? "=" + it->m_hint : "";
      arg_str = it->m_flags & OptionFlags::OptionalArgument ? "[=" + it->m_hint + "]" : arg_str;
      os << m_delim << it->m_long << arg_str;
   }
   os << std::endl;
   if (!m_options.empty()) {
      os << indent_str << std::string(usage_str.size(), ' ') << name;
      for (const auto &it : m_options) {
         std::string arg_str = it->m_flags & OptionFlags::RequiredArgument ? "=" + it->m_hint : "";
         arg_str = it->m_flags & OptionFlags::OptionalArgument ? "[=" + it->m_hint + "]" : arg_str;
         os << m_delim << it->m_short << arg_str;
      }
      os << std::endl;
      os << "Params:" << std::endl;
   }
   indent_str += "  ";
   for (const auto &it : m_options) {
      std::string arg_str = it->m_flags & OptionFlags::RequiredArgument ? it->m_hint : "";
      arg_str = it->m_flags & OptionFlags::OptionalArgument ? "[" + it->m_hint + "]" : arg_str;

      os << indent_str <<
         std::setw(max_short + 1) << std::left << it->m_short <<
         std::setw(max_long + 1) << std::left << it->m_long <<
         std::setw(max_req_arg + 2) << std::left << arg_str <<
         " " + it->m_description << std::endl;
   }
}

}
