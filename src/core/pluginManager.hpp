/**
 * @file
 * @brief Manages the loading and unloading of shared plugins in the PluginManager class.
 *
 * This class provides functionality for loading dynamic shared objects (plugins) from specified
 * directories, optionally searching them recursively. It supports unloading plugins either
 * automatically at exit or manually through a function call. The class uses the `dlopen()` and
 * `dlclose()` system calls for managing shared object libraries, and the `std::filesystem` library
 * to iterate over files in a directory.
 *
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>
#include <vector>

namespace ipxp {

/**
 * @brief Manages loading and unloading of plugins (shared objects).
 *
 * This class loads plugins from a specified directory (with optional recursion), unloads them,
 * and manages their state. Plugins are loaded with `dlopen()` and unloaded with `dlclose()`.
 *
 * The `unloadAtExit` flag determines if plugins should be automatically unloaded when the
 * `PluginManager` object is destroyed. If set to `false`, plugins remain loaded, which is useful
 * for debugging (e.g., with Valgrind).
 *
 * It can load plugins from individual files or all `.so` files in a directory (recursively).
 */
class PluginManager {
public:
	/**
	 * @brief Constructor for PluginManager.
	 *
	 * Initializes the PluginManager, optionally setting whether plugins should be unloaded
	 * automatically when the PluginManager object is destroyed (in the destructor).
	 *
	 * @param unloadAtExit A boolean flag that determines if plugins should be unloaded when the
	 * PluginManager object is destroyed. Defaults to `true`.
	 */
	PluginManager(bool unloadAtExit = true);

	/**
	 * @brief Destructor for PluginManager.
	 *
	 * If the `unloadAtExit` flag is set to `true`, this method will automatically unload
	 * all loaded plugins by calling `dlclose()` on each plugin handle.
	 */
	~PluginManager();

	/**
	 * @brief Load a plugin from a specified file path.
	 *
	 * This method loads a single plugin (shared object) from the provided file path. If the plugin
	 * cannot be loaded, it will log an error and throw a `std::runtime_error`.
	 *
	 * @param pluginPath The path to the plugin file (shared object).
	 * @throws std::runtime_error if loading the plugin fails.
	 */
	void loadPlugin(const std::string& pluginPath);

	/**
	 * @brief Load plugins from a specified directory.
	 *
	 * This method loads all `.so` plugins from the specified directory. Optionally, it can
	 * search subdirectories recursively for plugins. It uses `std::filesystem` to iterate over
	 * the directory contents and attempts to load each `.so` file as a plugin. If an error occurs
	 * while accessing the directory or loading a plugin, it will log the error and throw an
	 * exception.
	 *
	 * @param dirPath The path to the directory containing the plugins.
	 * @param recursive A boolean flag indicating whether to search subdirectories recursively.
	 *
	 * @throws std::runtime_error If there is an error accessing the directory or loading the
	 * plugins.
	 */
	void loadPlugins(const std::string& dirPath, bool recursive = false);

	/**
	 * @brief Unload all loaded plugins.
	 *
	 * This method unloads all currently loaded plugins by calling `dlclose()` on each plugin
	 * handle.
	 */
	void unloadPlugins();

private:
	std::vector<void*> m_pluginHandles;
	bool m_unloadAtExit;
};

} // namespace ipxp
