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

#include <config.h>

#include <dlfcn.h>

#include "pluginmgr.hpp"

namespace ipxp {

static PluginRecord *ipxp_plugins = nullptr;
static int ipxp_ext_cnt = 0;

void register_plugin(PluginRecord *rec)
{
   PluginRecord **tmp = &ipxp_plugins;
   while (*tmp) {
      tmp = &(*tmp)->m_next;
   }
   *tmp = rec;
}

int register_extension()
{
   return ipxp_ext_cnt++;
}

int get_extension_cnt()
{
   return ipxp_ext_cnt;
}

PluginManager::PluginManager() : m_last_rec(nullptr)
{
   register_loaded_plugins();
}

PluginManager::~PluginManager()
{
   // Remove (external) getters before unloading .so libs
   m_getters.clear();
   unload();
}

void PluginManager::register_plugin(const std::string &name, PluginGetter g)
{
   auto it = m_getters.find(name);
   if (it != m_getters.end()) {
      throw PluginManagerError(name + " plugin already registered");
   }
   m_getters[name] = g;
}

Plugin *PluginManager::get(const std::string &name)
{
   auto it = m_getters.find(name);
   if (it == m_getters.end()) {
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
   return plugins;
}

Plugin *PluginManager::load(const std::string &name)
{
   dlerror();

   void *handle = dlopen(name.c_str(), RTLD_LAZY);
   if (handle == nullptr) {
      std::string filename = std::string(PLUGINDIR) + "/input-" + name + ".so";
      handle = dlopen(filename.c_str(), RTLD_LAZY);
      if (handle == nullptr) {
         filename = std::string(PLUGINDIR) + "/output-" + name + ".so";
         handle = dlopen(filename.c_str(), RTLD_LAZY);
         if (handle == nullptr) {
            filename = std::string(PLUGINDIR) + "/process-" + name + ".so";
            handle = dlopen(filename.c_str(), RTLD_LAZY);
            if (handle == nullptr) {
               return nullptr;
            }
         }
      }
   }
   if (m_last_rec == nullptr || m_last_rec->m_next == nullptr) {
      dlclose(handle);
      return nullptr;
   }

   PluginRecord *rec = m_last_rec;
   if (rec == nullptr) {
      rec = ipxp_plugins;
   } else {
      rec = rec->m_next;
   }
   if (rec) {
      try {
         // Register plugin name from .so
         this->register_plugin(rec->m_name, rec->m_getter);
      } catch (PluginManagerError &e) {
         throw PluginManagerError("plugin " + rec->m_name + " from " + name + " library already registered");
      }
      if (rec->m_name != name) {
         // Register .so name
         this->register_plugin(name, rec->m_getter);
      }
      m_last_rec = rec;
      rec = rec->m_next;
   }
   if (m_last_rec && m_last_rec->m_next) {
      dlclose(handle);
      throw PluginManagerError("encountered shared library file with more than 1 plugin");
   }

   m_loaded_so.push_back({handle, name});
   return static_cast<Plugin *> (m_getters[name]());
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
      try {
         this->register_plugin(rec->m_name, rec->m_getter);
      } catch (PluginManagerError &e) {
         std::cerr << "Error: loading of internal plugins failed: " << e.what() << std::endl;
         exit(EXIT_FAILURE);
      }
      m_last_rec = rec;
      rec = rec->m_next;
   }
}

}
