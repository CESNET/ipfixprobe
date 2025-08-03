#pragma once

#include "flowRecordDynamicData.hpp"

#include <array>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include "tcpFlags.hpp"

#include "flowKey.hpp"

namespace ipxp {

static constexpr std::size_t MAX_FIELD_SIZE = 192;
static constexpr std::size_t MAX_PLUGIN_SIZE = 32;

using PluginsBitset = std::bitset<MAX_PLUGIN_SIZE>;
using FieldsBitset = std::bitset<MAX_FIELD_SIZE>;

struct DirectionalData {
	uint64_t timeStart = 0;
	uint64_t timeEnd = 0;
	uint64_t packets = 0;
	uint64_t bytes = 0;
    TcpFlags tcpFlags{};
};

class FlowRecord {
public:
	uint64_t hash;

	uint64_t timeCreation;
	uint64_t timeLastUpdate;

	FlowKey flowKey;

	DirectionalData dataForward = {};
	DirectionalData dataReverse = {};

	// Bitset of flow fields that were specified as present
	FieldsBitset fieldsAvailable = {};

	// Bitset of successfully constructed plugins (constructor accepted packet)
	PluginsBitset pluginsEnable = {};
	// Bitset of plugins that still wants to process packets of the flow
	PluginsBitset pluginsUpdate = {};

	template<typename Func>
	void forEachPlugin(Func&& func)
	{
		const auto& metadata = pluginData.getMetadata();
		for (std::size_t pluginOffset : metadata.getOffsets()) {
			auto* processPlugin = reinterpret_cast<ProcessPlugin*>(pluginData.get() + pluginOffset);
			func(processPlugin);
		}
	}

private:
	// Spaced reserved for plugin data (dynamically allocated)
	FlowRecordDynamicData pluginData;

	// Constructor is private to ensure that FlowRecord can only be created through
	// FlowRecordBuilder
	FlowRecord(std::size_t size)
		: pluginData(size)
	{
	}

	friend class FlowRecordBuilder;
};

} // namespace ipxp