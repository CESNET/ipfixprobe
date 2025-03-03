/**
 * \file benchmark.cpp
 * \brief Plugin for generating packets
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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
 *
 *
 *
 */

#include <random>
#include <chrono>
#include <cstdint>
#include <sys/time.h>

#include "benchmark.hpp"
#include <ipfixprobe/plugin.hpp>
#include <ipfixprobe/utils.hpp>
#include <ipfixprobe/packet.hpp>

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("benchmark", [](){return new Benchmark();});
   register_plugin(&rec);
}

Benchmark::Benchmark()
   : m_generatePacketFunc(nullptr), m_flowMode(BenchmarkMode::FLOW_1), m_maxDuration(BENCHMARK_DEFAULT_DURATION), m_maxPktCnt(BENCHMARK_DEFAULT_PKT_CNT),
     m_packetSizeFrom(BENCHMARK_DEFAULT_SIZE_FROM), m_packetSizeTo(BENCHMARK_DEFAULT_SIZE_TO), m_firstTs({0}), m_currentTs({0}), m_pktCnt(0)
{
}

Benchmark::~Benchmark()
{
   close();
}

void Benchmark::init(const char *params)
{
   BenchmarkOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   if (parser.m_mode == "1f") {
      generatePacket(&m_pkt);
      m_flowMode = BenchmarkMode::FLOW_1;
      m_generatePacketFunc = &Benchmark::generatePacketFlow1;
   } else if (parser.m_mode == "nf") {
      m_flowMode = BenchmarkMode::FLOW_N;
      m_generatePacketFunc = &Benchmark::generatePacketFlowN;
   } else {
      throw PluginError("invalid benchmark mode specified");
   }

   m_maxDuration = parser.m_duration;
   m_maxPktCnt = parser.m_pkt_cnt;
   m_packetSizeFrom = parser.m_pkt_size;
   m_packetSizeTo = parser.m_pkt_size;
   if (m_packetSizeFrom < 64) {
      throw PluginError("minimal packet size is 64 bytes");
   }

   if (parser.m_seed.empty()) {
      std::random_device rd;
      m_rndGen = std::mt19937(rd());
   } else {
      std::seed_seq seed (parser.m_seed.begin(),parser.m_seed.end());
      m_rndGen = std::mt19937(seed);
   }
   gettimeofday(&m_firstTs, nullptr);
}

void Benchmark::close()
{
}

InputPlugin::Result Benchmark::get(PacketBlock &packets)
{
   gettimeofday(&m_currentTs, nullptr);
   InputPlugin::Result res = check_constraints();
   if (res != InputPlugin::Result::PARSED) {
      return res;
   }

   packets.cnt = 0;
   packets.bytes = 0;
   for (size_t i = 0; i < packets.size; i++) {
      (this->*m_generatePacketFunc)(&(packets.pkts[i]));
      packets.cnt++;
      packets.bytes += packets.pkts[i].packet_len_wire;
      m_pktCnt++;
      if (m_maxPktCnt && m_pktCnt >= m_maxPktCnt) {
         break;
      }
   }
   m_seen += packets.cnt;
   m_parsed += packets.cnt;
   return res;
}

InputPlugin::Result Benchmark::check_constraints() const
{
   int tmp = m_currentTs.tv_usec - m_firstTs.tv_usec ;
   uint64_t duration = m_currentTs.tv_sec - m_firstTs.tv_sec + (tmp < 0 ? -1 : 0);

   if ((m_maxPktCnt != BENCHMARK_PKT_CNT_INF && m_pktCnt >= m_maxPktCnt) ||
       (m_maxDuration != BENCHMARK_DURATION_INF && duration >= m_maxDuration)) {
      return InputPlugin::Result::END_OF_FILE;
   }
   return InputPlugin::Result::PARSED;
}

void Benchmark::swapEndpoints(Packet *pkt)
{
   std::swap(pkt->src_mac, pkt->dst_mac);
   std::swap(pkt->src_ip, pkt->dst_ip);
   std::swap(pkt->src_port, pkt->dst_port);
}

void Benchmark::generatePacket(Packet *pkt)
{
   std::uniform_int_distribution<uint32_t> distrib;

   pkt->ts = m_currentTs;
   pkt->packet_len = std::uniform_int_distribution<uint16_t>(m_packetSizeFrom, m_packetSizeTo)(m_rndGen);
   pkt->packet_len_wire = pkt->packet_len;
   if (distrib(m_rndGen) & 1) {
      pkt->ethertype = 0x0800;
      pkt->ip_version = IP::v4;
      pkt->src_ip.v4 = distrib(m_rndGen);
      pkt->dst_ip.v4 = distrib(m_rndGen);
   } else {
      pkt->ethertype = 0x86DD;
      pkt->ip_version = IP::v6;
      for (int i = 0; i < 4; i++) {
         reinterpret_cast<uint32_t *>(pkt->src_ip.v6)[i] = distrib(m_rndGen);
         reinterpret_cast<uint32_t *>(pkt->dst_ip.v6)[i] = distrib(m_rndGen);
      }
   }

   pkt->src_port = distrib(m_rndGen);
   pkt->dst_port = distrib(m_rndGen);
   if (distrib(m_rndGen) & 1) {
      pkt->ip_proto = IPPROTO_TCP;
      pkt->tcp_flags = 0x18; // PSH ACK
      pkt->ip_payload_len = BENCHMARK_L4_SIZE_TCP;
   } else {
      pkt->ip_proto = IPPROTO_UDP;
      pkt->tcp_flags = 0;
      pkt->ip_payload_len = BENCHMARK_L4_SIZE_UDP;
   }
   int tmp = pkt->ip_payload_len + BENCHMARK_L2_SIZE + BENCHMARK_L3_SIZE;

   pkt->payload_len = std::uniform_int_distribution<uint16_t>(m_packetSizeFrom - tmp, m_packetSizeTo - tmp)(m_rndGen);
   pkt->ip_payload_len += pkt->payload_len;
   pkt->ip_len = pkt->ip_payload_len + BENCHMARK_L3_SIZE;
   pkt->packet_len = pkt->ip_len + BENCHMARK_L2_SIZE;

   pkt->packet = pkt->buffer;
   pkt->payload = pkt->packet + (pkt->packet_len - pkt->payload_len);

   static_assert(BENCHMARK_L2_SIZE + BENCHMARK_L3_SIZE +
      max(BENCHMARK_L4_SIZE_TCP, BENCHMARK_L4_SIZE_UDP) <= BENCHMARK_MIN_PACKET_SIZE, "minimal packet size is too low");
}

void Benchmark::generatePacketFlow1(Packet *pkt)
{
   int tmp = m_pkt.packet_len - m_pkt.payload_len; // Non payload size
   int newPayloadLength = std::uniform_int_distribution<uint16_t>(m_packetSizeFrom - tmp, m_packetSizeTo - tmp)(m_rndGen);
   int diff = newPayloadLength - m_pkt.payload_len;

   m_pkt.payload_len += diff;
   m_pkt.payload_len_wire += diff;
   m_pkt.ip_payload_len += diff;
   m_pkt.ip_len += diff;
   m_pkt.packet_len += diff;
   m_pkt.packet_len_wire += diff;

   m_pkt.ts = m_currentTs;
   swapEndpoints(&m_pkt);

   m_pkt.buffer = pkt->buffer;
   m_pkt.packet = m_pkt.buffer;
   m_pkt.payload = m_pkt.packet + (pkt->packet_len - pkt->payload_len);
   *pkt = m_pkt;
}

void Benchmark::generatePacketFlowN(Packet *pkt)
{
   generatePacket(pkt);
}

}
