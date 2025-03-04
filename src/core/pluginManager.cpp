/**
 * @file
 * @brief Implementation of PluginManager class for loading and unloading plugins.
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pluginManager.hpp"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include <dlfcn.h>

namespace ipxp {

namespace fs = std::filesystem;

static void clearErrorMessage()
{
	dlerror();
}

static void* openSharedObject(const std::string& path)
{
	const int dlFlags = RTLD_LAZY | RTLD_LOCAL;
	return dlopen(path.c_str(), dlFlags);
}

template<typename Iterator>
static bool isValidPlugin(const Iterator& entry)
{
	return entry.is_regular_file() && entry.path().extension() == ".so";
}

static void loadPluginsRecursive(const std::string& dirPath, PluginManager& pluginManager)
{
	/**
	 * Due to dependencies between plugins, we need to load them in a specific order.
	 * Plugins with "output" in their path should be loaded first.
	 */
	std::vector<fs::directory_entry> entries;

	for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
		if (isValidPlugin(entry)) {
			entries.push_back(entry);
		}
	}

	std::sort(
		entries.begin(),
		entries.end(),
		[](const fs::directory_entry& a, const fs::directory_entry& b) {
			bool aHasOutput = a.path().string().find("output") != std::string::npos;
			bool bHasOutput = b.path().string().find("output") != std::string::npos;
			return aHasOutput > bHasOutput;
		});

	for (const auto& entry : entries) {
		pluginManager.loadPlugin(entry.path().string());
	}
}

static void loadPluginsNonRecursive(const std::string& dirPath, PluginManager& pluginManager)
{
	for (const auto& entry : fs::directory_iterator(dirPath)) {
		if (isValidPlugin(entry)) {
			pluginManager.loadPlugin(entry.path().string());
		}
	}
}

PluginManager::PluginManager(bool unloadAtExit)
	: m_unloadAtExit(unloadAtExit)
{
}

void PluginManager::loadPlugins(const std::string& dirPath, bool recursive)
{
	const auto loadPluginsFunction = recursive ? loadPluginsRecursive : loadPluginsNonRecursive;

	try {
		loadPluginsFunction(dirPath, *this);
	} catch (const fs::filesystem_error& ex) {
		std::cerr << "Error accessing directory '" << dirPath << "': " << ex.what() << std::endl;
		// m_logger->error("Error accessing directory '{}': {}", dirPath, ex.what());
		throw std::runtime_error("PluginManager::loadPlugins() has failed.");
	}
}

void PluginManager::loadPlugin(const std::string& pluginPath)
{
	clearErrorMessage();
	void* pluginHandle = openSharedObject(pluginPath);

	if (!pluginHandle) {
		std::cerr << "Error loading plugin '" << pluginPath << "': " << dlerror() << std::endl;
		// m_logger->error(std::string(dlerror()));
		throw std::runtime_error("PluginManager::loadPlugin() has failed.");
	}

	// std::cerr << "Plugin '" << pluginPath << "' loaded." << std::endl;
	//  m_logger->info("Plugin '{}' loaded.", pluginPath);

	m_pluginHandles.emplace_back(pluginHandle);
}

PluginManager::~PluginManager()
{
	if (m_unloadAtExit) {
		unloadPlugins();
	}
}

void PluginManager::unloadPlugins()
{
	for (auto handle : m_pluginHandles) {
		dlclose(handle);
	}
	m_pluginHandles.clear();
}

} // namespace ipxp
