/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * @brief This file contains the definition of the `PluginFactory` class. The class is responsible
 * for registering plugins and creating instances of those plugins via generator functions. It
 * provides support for various types of object creation, including unique pointers, shared
 * pointers and in-place construction.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "pluginGenerator.hpp"
#include "pluginManifest.hpp"

#include <map>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <type_traits>

namespace ipxp {

/**
 * @brief Templated class `PluginFactory` is responsible for managing and creating plugin instances.
 *
 * The `PluginFactory` class provides a singleton-based interface for registering plugins
 * and generating their instances. It supports creating unique and shared pointers, as well as
 * objects constructed at pre-allocated memory. Each plugin is identified by a `PluginManifest`.
 *
 * @tparam Base The base class type that all plugins must inherit from.
 * @tparam Args The types of arguments that will be passed to the plugin constructors.
 */
template<typename Base, typename... Args>
class PluginFactory {
public:
	/**
	 * @brief Retrieves the singleton instance of `PluginFactory`.
	 *
	 * @return A reference to the singleton `PluginFactory` instance.
	 */
	static PluginFactory& getInstance()
	{
		static PluginFactory instance;
		return instance;
	}

	/**
	 * @brief Registers a plugin with the factory.
	 *
	 * This function registers a plugin by associating its manifest with its generator functions.
	 * The function enforces that the `Derived` type must inherit from the `Base` class.
	 *
	 * @tparam Derived The plugin type (class) that inherits from the `Base` class.
	 * @param manifest The manifest containing metadata about the plugin.
	 *
	 * @throw std::logic_error If `Derived` is not derived from `Base`.
	 */
	template<typename Derived>
	void registerPlugin(const PluginManifest& manifest)
	{
		static_assert(std::is_base_of<Base, Derived>::value, "Derived must be a subclass of Base");

		m_registeredPlugins[manifest] = createGenerators<Base, Derived, Args...>();
	}

	/**
	 * @brief Retrieves a list of all registered plugins.
	 *
	 * @return A vector of `PluginManifest` objects representing the registered plugins.
	 */
	[[nodiscard]] std::vector<PluginManifest> getRegisteredPlugins()
	{
		std::vector<PluginManifest> registeredPlugins;
		registeredPlugins.reserve(m_registeredPlugins.size());

		for (const auto& [pluginManifest, _] : m_registeredPlugins) {
			registeredPlugins.push_back(pluginManifest);
		}
		return registeredPlugins;
	}

	/**
	 * @brief Creates a unique pointer to a plugin instance.
	 *
	 * @param key The key identifying the plugin (from the manifest).
	 * @param args The arguments passed to the plugin constructor.
	 * @return A unique pointer to the plugin instance.
	 * @throws std::runtime_error If the plugin identified by the key is not registered.
	 * @throws Any exception from the plugin constructor.
	 */
	[[nodiscard]] std::unique_ptr<Base> createUnique(std::string_view key, Args... args) const
	{
		const auto& generators = getGenerators(key);
		return generators.uniqueGenerator(std::forward<Args>(args)...);
	}

	/**
	 * @brief Creates a shared pointer to a plugin instance.
	 *
	 * @param key The key identifying the plugin (from the manifest).
	 * @param args The arguments passed to the plugin constructor.
	 * @return A shared pointer to the plugin instance.
	 * @throws std::runtime_error If the plugin identified by the key is not registered.
	 * @throws Any exception from the plugin constructor.
	 */
	[[nodiscard]] std::shared_ptr<Base> createShared(std::string_view key, Args... args) const
	{
		const auto& generators = getGenerators(key);
		return generators.sharedGenerator(std::forward<Args>(args)...);
	}

	/**
	 * @brief Constructs a plugin instance at a pre-allocated memory location.
	 *
	 * @param key The key identifying the plugin (from the manifest).
	 * @param ptr The pre-allocated memory where the instance will be constructed.
	 * @param args The arguments passed to the plugin constructor.
	 * @return A pointer to the constructed plugin instance.
	 * @throws std::runtime_error If the plugin identified by the key is not registered.
	 * @throws Any exception from the plugin constructor.
	 */
	[[nodiscard]] Base* constructAt(std::string_view key, void* ptr, Args... args) const
	{
		const auto& generators = getGenerators(key);
		return generators.constructAtGenerator(ptr, std::forward<Args>(args)...);
	}

private:
	PluginFactory() = default;

	using Generators = BaseGenerators<Base, Args...>;

	Generators getGenerators(std::string_view key) const
	{
		const auto iter = m_registeredPlugins.find(key);
		if (iter == m_registeredPlugins.end()) {
			throw std::runtime_error(
				"PluginFactory::getGenerators() has failed. Plugin: '" + std::string(key)
				+ "' is not registered.");
		}

		return iter->second;
	}

	struct PluginManifestComparator {
		using is_transparent = void;

		bool operator()(const PluginManifest& lhs, const PluginManifest& rhs) const
		{
			return lhs.name < rhs.name;
		}

		bool operator()(const PluginManifest& lhs, std::string_view rhs) const
		{
			return lhs.name < rhs;
		}

		bool operator()(std::string_view lhs, const PluginManifest& rhs) const
		{
			return lhs < rhs.name;
		}
	};

	std::map<PluginManifest, Generators, PluginManifestComparator> m_registeredPlugins;
};

} // namespace ipxp
