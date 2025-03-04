/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * @brief This file contains the definition of the `PluginRegistrar` struct.
 * The struct is responsible for automatically registering a plugin with the `Factory`.
 * It ensures that the `Derived` type is properly registered with the factory under
 * the provided manifest.
 *
 * The `PluginRegistrar` template can be used to simplify the process of
 * plugin registration. By specifying the `Derived` type and the corresponding
 * `Factory`, this struct allows for easy integration of plugins into the
 * factory system at runtime.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "pluginFactory.hpp"
#include "pluginManifest.hpp"

#include <stdexcept>
#include <type_traits>

namespace ipxp {

/**
 * @brief Templated struct `PluginRegistrar` is responsible for automatically registering
 * a plugin with the specified `Factory` during construction.
 *
 * This struct registers a plugin with the factory at runtime. It allows for the specification of a
 * `Derived` type, which must be registered under the provided `PluginManifest`. This facilitates
 * the registration process, ensuring that the `Derived` class is integrated into the plugin system
 * seamlessly.
 *
 * @tparam Derived The derived class type being registered.
 * @tparam Factory The factory type responsible for managing plugins.
 *
 * @code
 * //// basePlugin.hpp
 *
 * // Example of a base plugin class definition
 * class BasePlugin {
 * public:
 *     virtual void doSomething() = 0; // Pure virtual function
 * };
 *
 * // forward declaration of the factory type
 * template<typename Base, typename... Args>
 * class PluginFactory;
 *
 * // define the factory type
 * // std::string is the type of the constructor parameter
 * using BasePluginFactory = PluginFactory<BasePlugin, const std::string>;
 *
 * //// plugin.hpp
 * #include "basePlugin.hpp"
 *
 * class DerivedPlugin : public BasePlugin {
 * public:
 *     // Constructor requiring a string parameter
 *     DerivedPlugin(const std::string& params) {
 *         // Initialize plugin with provided parameters
 *     }
 *
 *     void doSomething() override {
 *         // Implementation of the plugin's functionality
 *     }
 * };
 *
 * //// plugin.cpp
 *
 * #include "plugin.hpp"
 * #include "pluginFactoryRegistration.hpp"
 *
 * // Registering the plugin with the factory
 * // This ensures that the required constructor exists
 * static const PluginRegistrar<DerivedPlugin, BasePluginFactory>
 *     derivedRegistrator(pluginManifest);
 * @endcode
 */
template<typename Derived, typename Factory>
struct PluginRegistrar {
	/**
	 * @brief Constructor that automatically registers the `Derived` class with the factory.
	 *
	 * This constructor registers the `Derived` class plugin with the specified factory,
	 * using the provided manifest.
	 *
	 * @param manifest The manifest containing metadata about the plugin.
	 */
	explicit PluginRegistrar(const PluginManifest& manifest)
	{
		Factory::getInstance().template registerPlugin<Derived>(manifest);
	}
};

} // namespace ipxp