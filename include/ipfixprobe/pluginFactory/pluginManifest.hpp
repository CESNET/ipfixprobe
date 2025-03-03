/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Definition of the PluginManifest struct and related utilities.
 *
 * This file contains the definition of the PluginManifest struct, which represents
 * metadata and functionalities associated with a plugin. It also defines a custom comparator for
 * PluginManifest instances.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <functional>
#include <string>

namespace ipxp {

/**
 * @brief Struct representing the metadata and functionalities associated with a plugin.
 *
 * The PluginManifest struct encapsulates important details about a plugin, such as its
 * name, description, version, and the required API version. This metadata is used to
 * identify and manage plugins within the system.
 */
struct PluginManifest {
	std::string name; ///< Name of the plugin.
	std::string description; ///< Description of the plugin.
	std::string pluginVersion; ///< Version of the plugin.
	std::string apiVersion; ///< Required API version.
	std::function<void()> usage; ///< Function pointer to the plugin's usage.
};

/**
 * @brief Custom less-than comparator for PluginManifest instances.
 *
 * This operator allows for sorting PluginManifest instances based on their name.
 *
 * @param lhs Left-hand side PluginManifest instance.
 * @param rhs Right-hand side PluginManifest instance.
 * @return True if the name of lhs is lexicographically less than the name of rhs, false otherwise.
 */
inline bool operator<(const PluginManifest& lhs, const PluginManifest& rhs)
{
	return lhs.name < rhs.name;
}

/**
 * @brief Custom equality operator for PluginManifest instances.
 *
 * This operator allows for comparison between two PluginManifest instances based on their name.
 *
 * @param lhs Left-hand side PluginManifest instance.
 * @param rhs Right-hand side PluginManifest instance.
 * @return True if the names of both instances are equal, false otherwise.
 */
inline bool operator==(const PluginManifest& lhs, const PluginManifest& rhs)
{
	return lhs.name == rhs.name;
}

} // namespace ipxp