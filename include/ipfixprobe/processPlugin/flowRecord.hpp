#pragma once

#include "timestamp.hpp"
#include "flowKey.hpp"
#include "directionalField.hpp"
#include "tcpFlags.hpp"
#include "packet.hpp"

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
	TCPFlags tcpFlags = 0;
};

enum class FlowEndReason : uint8_t {
	FLOW_END_INACTIVE = 0x01,
	FLOW_END_ACTIVE = 0x02,
	FLOW_END_EOF = 0x03,
	FLOW_END_FORCED = 0x04,
	FLOW_END_NO_RES = 0x05
};

class FlowRecord {
public:
	uint64_t hash;

	Timestamp timeCreation;
	Timestamp timeLastUpdate;

	FlowKey flowKey;
	DirectionalField<MACAddress> macAddress;

	DirectionalField<DirectionalData> directionalData;

	FlowEndReason endReason;

	// Bitset of flow fields that were specified as present
	mutable FieldsBitset fieldsAvailable = {};
	// Bitset of successfully constructed plugins (constructor accepted packet)
	PluginsBitset pluginsConstructed = {};
	// Bitset of plugins that still wants to process packets of the flow
	PluginsBitset pluginsUpdate = {};
	// Bitset of plugins that are available for the flow
	// TODO GET BACK CONST ?
	PluginsBitset pluginsAvailable;

	void erase()
	{
		hash = 0;
		timeCreation = timeLastUpdate = {};
		flowKey = {};
		//directionalData = {};

		/*memset(&m_flow.time_first, 0, sizeof(m_flow.time_first));
		memset(&m_flow.time_last, 0, sizeof(m_flow.time_last));
		m_flow.ip_version = 0;
		m_flow.ip_proto = 0;
		memset(&m_flow.src_ip, 0, sizeof(m_flow.src_ip));
		memset(&m_flow.dst_ip, 0, sizeof(m_flow.dst_ip));
		m_flow.src_port = 0;
		m_flow.dst_port = 0;
		m_flow.src_packets = 0;
		m_flow.dst_packets = 0;
		m_flow.src_bytes = 0;
		m_flow.dst_bytes = 0;
		m_flow.src_tcp_flags = 0;
		m_flow.dst_tcp_flags = 0;*/
	}

	void reuse()
	{
		/*m_flow.remove_extensions();
		m_flow.time_first = m_flow.time_last;
		m_flow.src_packets = 0;
		m_flow.dst_packets = 0;
		m_flow.src_bytes = 0;
		m_flow.dst_bytes = 0;
		m_flow.src_tcp_flags = 0;
		m_flow.dst_tcp_flags = 0;*/
	}

	constexpr bool isEmpty() const noexcept
	{
		return hash == 0;
	}

	/*constexpr bool belongs(uint64_t value) const noexcept
	{
		return hash == value;
	}*/

	// TODO remove hashval
	void createFrom(const Packet& packet, uint64_t hashval)
	{
		directionalData[Direction::Forward].packets = 1;
		directionalData[Direction::Forward].bytes = packet.ip_len;

		
		flowKey.srcPort = packet.src_port;
		flowKey.dstPort = packet.dst_port;
		flowKey.l4Protocol = packet.ip_proto;

		hash = hashval;

		timeCreation = packet.ts;
		timeLastUpdate = packet.ts;

		macAddress[Direction::Forward] 
			= std::span<const std::byte, 6>(
				reinterpret_cast<const std::byte*>(packet.src_mac), 6);
		macAddress[Direction::Reverse] 
			= std::span<const std::byte, 6>(
				reinterpret_cast<const std::byte*>(packet.dst_mac), 6);

		if (packet.ip_version == IP::v4) {
			flowKey.srcIp = packet.src_ip.v4;
			flowKey.dstIp = packet.dst_ip.v4;
		} else if (packet.ip_version == IP::v6) {
			flowKey.srcIp = std::span<const std::byte, 16>(
				reinterpret_cast<const std::byte*>(packet.src_ip.v6), 16);
			flowKey.dstIp = std::span<const std::byte, 16>(
				reinterpret_cast<const std::byte*>(packet.dst_ip.v6), 16);
		}
	}

	void update(const Packet& packet, bool src)
	{
		/*m_flow.time_last = pkt.ts;
		if (src) {
			m_flow.src_packets++;
			m_flow.src_bytes += pkt.ip_len;

			if (pkt.ip_proto == IPPROTO_TCP) {
				m_flow.src_tcp_flags |= pkt.tcp_flags;
			}
		} else {
			m_flow.dst_packets++;
			m_flow.dst_bytes += pkt.ip_len;

			if (pkt.ip_proto == IPPROTO_TCP) {
				m_flow.dst_tcp_flags |= pkt.tcp_flags;
			}
		}*/
	}

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