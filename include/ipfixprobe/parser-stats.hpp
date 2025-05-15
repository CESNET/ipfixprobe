/**
 * \file
 * \brief Definition of the ParserStats structure for storing parser statistics
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2024
 */
/*
 * Copyright (C) 2024 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 */

#pragma once

#include "../../src/plugins/input/parser/topPorts.hpp"

#include <array>
#include <cstdint>
#include <string>

#include <ipfixprobe/packet.hpp>
#include <telemetry.hpp>

namespace ipxp {

static constexpr std::size_t MAX_VLAN_ID = 4096;

class PacketSizeHistogram {
public:
	static constexpr std::size_t HISTOGRAM_SIZE = 10;

	struct Value {
		uint64_t packets = 0;
		uint64_t bytes = 0;
	};

	PacketSizeHistogram()
	{
		for (uint16_t bucketID = 0; bucketID < 8192; ++bucketID) {
			if (bucketID <= 64) {
				m_size_to_bucket[bucketID] = 0;
			} else if (bucketID < 128) {
				m_size_to_bucket[bucketID] = 1;
			} else if (bucketID < 256) {
				m_size_to_bucket[bucketID] = 2;
			} else if (bucketID < 512) {
				m_size_to_bucket[bucketID] = 3;
			} else if (bucketID < 1024) {
				m_size_to_bucket[bucketID] = 4;
			} else if (bucketID < 1518) {
				m_size_to_bucket[bucketID] = 5;
			} else if (bucketID < 2048) {
				m_size_to_bucket[bucketID] = 6;
			} else if (bucketID < 4096) {
				m_size_to_bucket[bucketID] = 7;
			} else if (bucketID < 8192) {
				m_size_to_bucket[bucketID] = 8;
			} else {
				m_size_to_bucket[bucketID] = 9;
			}
		}
	}

	void update(uint16_t size)
	{
		if (size < 8192) {
			const std::size_t bucket = m_size_to_bucket[size];
			m_histogram[bucket].packets++;
			m_histogram[bucket].bytes += size;
		} else {
			m_histogram[HISTOGRAM_SIZE - 1].packets++;
			m_histogram[HISTOGRAM_SIZE - 1].bytes += size;
		}
	}

	Value get_bucket_value(std::size_t bucket) const
	{
		if (bucket < HISTOGRAM_SIZE) {
			return m_histogram[bucket];
		}
		return {};
	}

	std::string get_bucket_name(std::size_t bucket) const
	{
		if (bucket == 0) {
			return "0-64";
		} else if (bucket == 1) {
			return "65-127";
		} else if (bucket == 2) {
			return "128-255";
		} else if (bucket == 3) {
			return "256-511";
		} else if (bucket == 4) {
			return "512-1023";
		} else if (bucket == 5) {
			return "1024-1518";
		} else if (bucket == 6) {
			return "1519-2047";
		} else if (bucket == 7) {
			return "2048-4095";
		} else if (bucket == 8) {
			return "4096-8191";
		}
		return "8192+";
	}

private:
	std::array<Value, HISTOGRAM_SIZE> m_histogram = {};
	std::array<uint8_t, 8192> m_size_to_bucket = {};
};

struct VlanStats {
	void update(const Packet& pkt)
	{
		if (pkt.ip_version == IP::v4) {
			ipv4_packets++;
			ipv4_bytes += pkt.packet_len;
		} else if (pkt.ip_version == IP::v6) {
			ipv6_packets++;
			ipv6_bytes += pkt.packet_len;
		}

		if (pkt.ip_proto == IPPROTO_TCP) {
			tcp_packets++;
		} else if (pkt.ip_proto == IPPROTO_UDP) {
			udp_packets++;
		}

		total_packets++;
		total_bytes += pkt.packet_len;

		size_histogram.update(pkt.packet_len);
	}

	uint64_t ipv4_packets;
	uint64_t ipv6_packets;
	uint64_t ipv4_bytes;
	uint64_t ipv6_bytes;

	uint64_t tcp_packets;
	uint64_t udp_packets;

	uint64_t total_packets;
	uint64_t total_bytes;

	PacketSizeHistogram size_histogram;
};

/**
 * \brief Structure for storing parser statistics.
 */
struct ParserStats {
	ParserStats(size_t top_ports_count)
		: top_ports(top_ports_count)
		, mpls_packets(0)
		, vlan_packets(0)
		, pppoe_packets(0)
		, trill_packets(0)
		, ipv4_packets(0)
		, ipv6_packets(0)
		, tcp_packets(0)
		, udp_packets(0)
		, seen_packets(0)
		, unknown_packets(0)
	{
	}

	TopPorts top_ports;

	uint64_t mpls_packets;
	uint64_t vlan_packets;
	uint64_t pppoe_packets;
	uint64_t trill_packets;

	uint64_t ipv4_packets;
	uint64_t ipv6_packets;
	uint64_t ipv4_bytes;
	uint64_t ipv6_bytes;

	uint64_t tcp_packets;
	uint64_t udp_packets;

	uint64_t seen_packets;
	uint64_t unknown_packets;

	VlanStats vlan_stats[MAX_VLAN_ID];
};

} // namespace ipxp
