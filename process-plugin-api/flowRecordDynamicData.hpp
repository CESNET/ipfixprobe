#pragma once

#include <cstddef>
#include <iostream>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

// #include "processPlugin.hpp"

class ProcessPlugin;

class PluginsMetadata {
public:
	std::span<const std::size_t> getOffsets() const
	{
		return std::span<const std::size_t>(pluginsOffsets, pluginsCount);
	}

	std::size_t pluginsCount;
	std::size_t pluginsOffsets[];
};

static_assert(
	std::is_trivially_constructible_v<PluginsMetadata>,
	"PluginsMetadata must be trivially constructible.");
static_assert(
	std::is_standard_layout_v<PluginsMetadata>,
	"PluginsMetadata must be standard layout.");

struct FlowRecordDynamicData {
	FlowRecordDynamicData(size_t size) { data = std::make_unique<std::byte[]>(size); }

	FlowRecordDynamicData(const FlowRecordDynamicData&) = default;
	FlowRecordDynamicData(FlowRecordDynamicData&& other) noexcept
	{
		data = std::move(other.data);
		other.data = nullptr;
	}

	template<typename Func>
	void forEachPlugin(Func&& func)
	{
		for (std::size_t offset : getMetadata().getOffsets()) {
			auto* plugin = reinterpret_cast<ProcessPlugin*>(data.get() + offset);
			func(plugin);
		}
	}

	std::byte* get() { return data.get(); }
	const std::byte* get() const { return data.get(); }

	PluginsMetadata& getMetadata() { return *reinterpret_cast<PluginsMetadata*>(data.get()); }

	~FlowRecordDynamicData()
	{
		if (!data) {
			return;
		}
		forEachPlugin([](ProcessPlugin* plugin) { std::destroy_at(plugin); });
	}

private:
	std::unique_ptr<std::byte[]> data;
};

#if 0

class PluginData {
public:
	PluginData(std::size_t size)
		: data(new std::byte[size])
	{
	}

	PluginData(PluginData&& other)
	{
		data = other.data;
		other.data = nullptr;
	}

	const Metadata& getMetadata() const noexcept
	{
		return *reinterpret_cast<const Metadata*>(data);
	}

	std::byte* get() { return data; }
	const std::byte* get() const { return data; }

	~PluginData()
	{
		if (!data) {
			return;
		}
		for (std::size_t i = 0; i < getMetadata().count; ++i) {
		    /*
			ProcessPlugin* processPlugin
				= reinterpret_cast<ProcessPlugin*>(data + getMetadata().offsets[i]);
			std::destroy_at(processPlugin);
			*/
		}

		delete[] data;
	}

private:
	std::byte* data = nullptr;
};

#endif
