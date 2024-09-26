/**
 * \file plugin.hpp
 * \brief Generic interface of plugin
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
#ifndef IPXE_PLUGIN_HPP
#define IPXE_PLUGIN_HPP

#include <exception>
#include <string>

#include "options.hpp"

namespace ipxp {

class Plugin;
typedef std::function<Plugin *()> PluginGetter;

struct PluginRecord {
   std::string m_name;
   PluginGetter m_getter;
   PluginRecord *m_next;

   PluginRecord(const std::string &name, PluginGetter getter)
      : m_name(name), m_getter(getter), m_next(nullptr)
   {
   }
};

void register_plugin(PluginRecord *rec);

class Plugin
{
public:
   Plugin() {}
   virtual ~Plugin() {}

   virtual void init(const char *params) {}
   virtual void close() {}

   virtual OptionsParser *get_parser() const = 0;
   virtual std::string get_name() const = 0;
};

class PluginException : public std::runtime_error
{
public:
   explicit PluginException(const std::string &msg) : std::runtime_error(msg) {}
   explicit PluginException(const char *msg) : std::runtime_error(msg) {}
};

class PluginError : public PluginException
{
public:
   explicit PluginError(const std::string &msg) : PluginException(msg) {}
   explicit PluginError(const char *msg) : PluginException(msg) {}
};

class PluginExit : public PluginException
{
public:
   explicit PluginExit(const std::string &msg) : PluginException(msg) {}
   explicit PluginExit(const char *msg) : PluginException(msg) {}
   explicit PluginExit() : PluginException("") {}
};

}
#endif /* IPXE_PLUGIN_HPP */
