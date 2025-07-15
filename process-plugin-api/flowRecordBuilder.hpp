#pragma once

#include "flowRecord.hpp"

#include <cstddef>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
#include <vector>

// #include <ipfixprobe/pluginFactory/pluginFactory.hpp>
#include "dummyProcessPlugin.hpp"
#include "processPlugin.hpp"

static size_t alignUp(size_t offset, size_t alignment)
{
	return (offset + alignment - 1) & ~(alignment - 1);
}

static std::byte* alignPtr(std::byte* ptr, size_t alignment)
{
	return reinterpret_cast<std::byte*>(
		(reinterpret_cast<uintptr_t>(ptr) + alignment - 1) & ~(alignment - 1));
}

class FlowRecordBuilder {
public:
	template<typename... Args>
	void addProcessPlugin(const std::string& pluginName, Args&&... args)
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		// auto& pluginFactory = ProcessPluginFactory::getInstance();

		PluginPrototype pluginPrototype = {
			.name = pluginName,
			.size = 5 * 64, // TODO
			.alignment = 8, // TODO
			.prototype = std::make_unique<DummyPlugin>(std::forward<Args>(
				args)...), // pluginFactory.createUnique(pluginName, std::forward<Args>(args)...),
		};

		std::cout << "Adding plugin '" << pluginName << "' with size " << pluginPrototype.size
				  << " and alignment " << pluginPrototype.alignment << "\n";

		m_pluginPrototypes.push_back(std::move(pluginPrototype));
	}

	void disableProcessPlugin(const std::string& pluginName)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		for (auto& plugin : m_pluginPrototypes) {
			if (plugin.name == pluginName) {
				plugin.isEnabled = false;
				std::cout << "Plugin '" << pluginName << "' has been disabled\n";
				return;
			}
		}
		std::cout << "Plugin '" << pluginName << "' not found\n";
	}

	void enableProcessPlugin(const std::string& pluginName)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		for (auto& plugin : m_pluginPrototypes) {
			if (plugin.name == pluginName) {
				plugin.isEnabled = true;
				std::cout << "Plugin '" << pluginName << "' has been enabled\n";
				return;
			}
		}
		std::cout << "Plugin '" << pluginName << "' not found\n";
	}

	FlowRecord build()
	{
		if (m_pluginPrototypes.empty()) {
			throw std::runtime_error("No plugins added");
		}

		// Sort plugins by alignment and size
		std::sort(
			m_pluginPrototypes.begin(),
			m_pluginPrototypes.end(),
			[](const PluginPrototype& a, const PluginPrototype& b) {
				return (a.alignment > b.alignment)
					|| (a.alignment == b.alignment && a.size > b.size);
			});

		// TODO only if plugins are enabled
		size_t totalSize = sizeof(PluginsMetadata) + m_pluginPrototypes.size() * sizeof(size_t);
		for (const auto& plugin : m_pluginPrototypes) {
			totalSize = alignUp(totalSize, plugin.alignment) + plugin.size;
		}

		FlowRecord record(totalSize);

		std::byte* buffer = record.pluginData.get();
		PluginsMetadata& metadata = record.pluginData.getMetadata();
		buffer += sizeof(PluginsMetadata) + m_pluginPrototypes.size() * sizeof(size_t);

		metadata.pluginsCount = m_pluginPrototypes.size();

		// Clone each plugin into the buffer
		for (size_t i = 0; i < m_pluginPrototypes.size(); ++i) {
			buffer = alignPtr(buffer, m_pluginPrototypes[i].alignment);
			metadata.pluginsOffsets[i] = buffer - record.pluginData.get();
			m_pluginPrototypes[i].prototype->clone(buffer);
			buffer += m_pluginPrototypes[i].size;
		}

		return record;
	}

private:
	struct PluginPrototype {
		std::string name;
		std::size_t size;
		std::size_t alignment;
		std::unique_ptr<ProcessPlugin> prototype;
		bool isEnabled = true;
	};

	std::mutex m_mutex;
	std::vector<PluginPrototype> m_pluginPrototypes;
};
