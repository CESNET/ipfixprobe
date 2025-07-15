#pragma once

#include "flowRecordDynamicData.hpp"

#include <array>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>

static constexpr std::size_t MAX_FIELD_SIZE = 192;
static constexpr std::size_t MAX_PLUGIN_SIZE = 32;

using PluginsBitset = std::bitset<MAX_PLUGIN_SIZE>;
using FieldsBitset = std::bitset<MAX_FIELD_SIZE>;

union IPAddress {
	std::array<uint8_t, 16> u8;
	std::array<uint16_t, 8> u16;
	std::array<uint32_t, 4> u32;
	std::array<uint64_t, 2> u64;

	IPAddress() { std::memset(&u8, 0, sizeof(u8)); };
	IPAddress(uint32_t ipv4)
	{
		(void) ipv4; // Suppress unused warning
	};
	IPAddress(const std::array<uint8_t, 16>& ipv6)
	{
		(void) ipv6; // Suppress unused warning
	};
	// const bool isIPv4() {};
	// const bool isIPv6() {};
	//  TODO: comparison functions,...
};

struct DirectionalData {
	uint64_t timeStart = 0;
	uint64_t timeEnd = 0;
	uint64_t packets = 0;
	uint64_t bytes = 0;
};

struct FlowKey {
	IPAddress srcIp;
	IPAddress dstIp;
	uint16_t srcPort;
	uint16_t dstPort;
	uint8_t l4Protocol;
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
