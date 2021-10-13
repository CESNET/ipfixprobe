/**
 * \file pluginmgr.hpp
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

#ifndef IPXP_PLUGIN_MANAGER_HPP
#define IPXP_PLUGIN_MANAGER_HPP

#include <functional>
#include <exception>
#include <string>
#include <vector>
#include <map>

#include <ipfixprobe/plugin.hpp>

namespace ipxp {

class PluginManagerError : public std::runtime_error
{
public:
   explicit PluginManagerError(const std::string &msg) : std::runtime_error(msg) {}
   explicit PluginManagerError(const char *msg) : std::runtime_error(msg) {}
};

class PluginManager
{
public:

   PluginManager();
   ~PluginManager();
   void register_plugin(const std::string &name, PluginGetter g);
   Plugin *get(const std::string &name);
   std::vector<Plugin *> get() const;
   Plugin *load(const std::string &name);

private:
   struct LoadedPlugin {
      void *m_handle;
      std::string m_file;
   };

   std::map<std::string, PluginGetter> m_getters;
   std::vector<LoadedPlugin> m_loaded_so;
   PluginRecord *m_last_rec;

   void unload();
   void register_loaded_plugins();
};

}
#endif /* IPXP_PLUGIN_MANAGER_HPP */
