/**
 * \file pluginmgr.cpp
 * \brief Plugin manager factory
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

#include <dlfcn.h>

#include "pluginmgr.hpp"

namespace ipxp {

static PluginRecord *ipxp_plugins = nullptr;

void register_plugin(PluginRecord *rec)
{
   PluginRecord **tmp = &ipxp_plugins;
   while (*tmp) {
      tmp = &(*tmp)->m_next;
   }
   *tmp = rec;
}

PluginManager::PluginManager() : m_last_rec(nullptr)
{
   register_loaded_plugins();
}

PluginManager::~PluginManager()
{
   unload();
}

void PluginManager::register_plugin(const std::string &name, PluginGetter g)
{
   auto it = m_getters.find(name);
   if (it != m_getters.end()) {
      throw PluginManagerError("plugin already registered");
   }
   m_getters[name] = g;
}

void PluginManager::register_plugin(const std::string &name, void *(*g)())
{
   auto it = m_getters_c.find(name);
   if (it != m_getters_c.end()) {
      throw PluginManagerError("plugin already registered");
   }
   m_getters_c[name] = g;
}

Plugin *PluginManager::get(const std::string &name)
{
   auto it = m_getters.find(name);
   if (it == m_getters.end()) {
      auto itc = m_getters_c.find(name);
      if (itc != m_getters_c.end()) {
         return static_cast<Plugin *>(m_getters_c[name]());
      }
      return load(name);
   }
   return m_getters[name]();
}

std::vector<Plugin *> PluginManager::get() const
{
   std::vector<Plugin *> plugins;
   for (auto &it : m_getters) {
      plugins.push_back((it.second)());
   }
   for (auto &it : m_getters_c) {
      plugins.push_back(static_cast<Plugin *>(it.second()));
   }

   return plugins;
}

Plugin *PluginManager::load(const std::string &name)
{
   dlerror();
   void *handle = dlopen(name.c_str(), RTLD_LAZY);
   if (handle == nullptr) {
      return nullptr;
   }
   if (m_last_rec == nullptr || m_last_rec->m_next == nullptr) {
      dlclose(handle);
      return nullptr;
   }

   register_loaded_plugins();
   m_loaded_so.push_back({handle, name});
   return static_cast<Plugin *> (m_getters_c[name]());
}

void PluginManager::unload()
{
   for (auto &it : m_loaded_so) {
      dlclose(it.m_handle);
   }
   m_loaded_so.clear();
}

void PluginManager::register_loaded_plugins()
{
   PluginRecord *rec = m_last_rec;
   if (rec == nullptr) {
      rec = ipxp_plugins;
   }
   while (rec) {
      this->register_plugin(rec->m_name, rec->m_getter);
      m_last_rec = rec;
      rec = rec->m_next;
   }
}

}
