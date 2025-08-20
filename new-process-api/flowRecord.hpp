#pragma once

#include "timestamp.hpp"

#include <array>
#include <bitset>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <span>

namespace ipxp {

static constexpr std::size_t MAX_PLUGIN_COUNT = 32;
static constexpr std::size_t MAX_FIELD_COUNT = 192;

using PluginsBitset = std::bitset<MAX_PLUGIN_COUNT>;
using FieldsBitset = std::bitset<MAX_FIELD_COUNT>;

struct PluginLayoutItem {
	std::size_t offset;
};

struct FlowRecordLayout {
	std::size_t flowKeyOffset;
	std::size_t pluginTableOffset;
};

struct FlowRecordPluginTable {
	std::size_t pluginCount;
	PluginLayoutItem pluginDataLayouts[1];
};

struct DirectionalData {
	Timestamp timeStart;
	Timestamp timeEnd;
	uint64_t packets = 0;
	uint64_t bytes = 0;
	uint8_t tcpFlags = 0;
};

class FlowRecord {
public:
	// Bitset of flow fields that were specified as present
	mutable FieldsBitset fieldsAvailable = {};
	// Bitset of successfully constructed plugins (constructor accepted packet)
	PluginsBitset pluginsConstructed = {};
	// Bitset of plugins that still wants to process packets of the flow
	PluginsBitset pluginsUpdate = {};
	// Bitset of plugins that are available for the flow
	const PluginsBitset pluginsAvailable;

	void* getPluginContext(std::size_t pluginIndex)
	{
		std::span<const PluginLayoutItem> layouts = getPluginTable();

		assert(pluginIndex < layouts.size() && "Invalid plugin index");
		assert(
			layouts[pluginIndex].offset != std::numeric_limits<std::size_t>::max()
			&& "Plugin is disabled, cannot get context");

		return reinterpret_cast<void*>(
			reinterpret_cast<std::byte*>(this) + layouts[pluginIndex].offset);
	}

	// TODO PRIVATE
	FlowRecord(PluginsBitset pluginsAvailable = {})
		: pluginsAvailable(pluginsAvailable)
	{
	}

private:
	friend class FlowRecordBuilder;

	std::span<const PluginLayoutItem> getPluginTable() const noexcept
	{
		const FlowRecordPluginTable* pluginTable = reinterpret_cast<const FlowRecordPluginTable*>(
			reinterpret_cast<const std::byte*>(this) + m_layout.pluginTableOffset);

		std::cout << "Plugin table located at: " << m_layout.pluginTableOffset << " offset\n";
		std::cout << "Plugin count: " << pluginTable->pluginCount << "\n";

		return std::span<const PluginLayoutItem>(
			&pluginTable->pluginDataLayouts[0],
			pluginTable->pluginCount);
	}

	FlowRecordLayout m_layout;
};

class FlowRecordDeleter {
public:
	explicit FlowRecordDeleter(std::size_t alignment)
		: m_alignment(alignment)
	{
	}

	void operator()(FlowRecord* ptr) const noexcept
	{
		if (ptr) {
			ptr->~FlowRecord();
			::operator delete(ptr, std::align_val_t(m_alignment));
		}
	}

private:
	std::size_t m_alignment;
};

using FlowRecordUniquePtr = std::unique_ptr<FlowRecord, FlowRecordDeleter>;

} // namespace ipxp