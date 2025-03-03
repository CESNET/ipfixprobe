/**
 * \file benchmark.hpp
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
#ifndef IPXP_INPUT_BENCHMARK_HPP
#define IPXP_INPUT_BENCHMARK_HPP

#include <random>
#include <chrono>
#include <string>
#include <cstdint>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

#define BENCHMARK_L2_SIZE     14
#define BENCHMARK_L3_SIZE     20
#define BENCHMARK_L4_SIZE_TCP 20
#define BENCHMARK_L4_SIZE_UDP 8

#define BENCHMARK_MIN_PACKET_SIZE   64
#define BENCHMARK_PKT_CNT_INF       0
#define BENCHMARK_FLOW_CNT_INF      0
#define BENCHMARK_DURATION_INF      0

#define BENCHMARK_DEFAULT_DURATION  10 // 10s
#define BENCHMARK_DEFAULT_FLOW_CNT  BENCHMARK_FLOW_CNT_INF
#define BENCHMARK_DEFAULT_PKT_CNT   BENCHMARK_PKT_CNT_INF
#define BENCHMARK_DEFAULT_SIZE_FROM 512
#define BENCHMARK_DEFAULT_SIZE_TO   512

class BenchmarkOptParser : public OptionsParser
{
public:
   std::string m_mode;
   std::string m_seed;
   uint64_t m_duration;
   uint64_t m_pkt_cnt;
   uint16_t m_pkt_size;
   uint64_t m_link;

   BenchmarkOptParser() : OptionsParser("benchmark", "Input plugin for various benchmarking purposes"),
      m_mode("1f"), m_seed(""), m_duration(0), m_pkt_cnt(0), m_pkt_size(BENCHMARK_DEFAULT_SIZE_FROM), m_link(0)
   {
      register_option("m", "mode", "STR", "Benchmark mode 1f (1x N-packet flow) or nf (Nx 1-packet flow)", [this](const char *arg){m_mode = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("S", "seed", "STR", "String seed for random generator", [this](const char *arg){m_seed = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("d", "duration", "TIME", "Duration in seconds",
         [this](const char *arg){try {m_duration = str2num<decltype(m_duration)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("p", "count", "SIZE", "Packet count",
         [this](const char *arg){try {m_pkt_cnt = str2num<decltype(m_pkt_cnt)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("s", "size", "SIZE", "Packet size",
         [this](const char *arg){try {m_pkt_size = str2num<decltype(m_pkt_size)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("I", "id", "NUM", "Link identifier number",
         [this](const char *arg){try {m_link = str2num<decltype(m_link)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
   }
};

class Benchmark : public InputPlugin
{
public:
   enum class BenchmarkMode {
      FLOW_1, /* 1x N-packet flow */
      FLOW_N  /* Nx 1-packet flows */
   };
   Benchmark();
   ~Benchmark();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new BenchmarkOptParser(); }
   std::string get_name() const { return "benchmark"; }

   InputPlugin::Result get(PacketBlock &packets);

private:
   void (Benchmark::*m_generatePacketFunc)(Packet *);
   BenchmarkMode m_flowMode;
   uint64_t m_maxDuration;
   uint64_t m_maxPktCnt;
   uint16_t m_packetSizeFrom;
   uint16_t m_packetSizeTo;

   std::mt19937 m_rndGen;
   Packet m_pkt;
   struct timeval m_firstTs;
   struct timeval m_currentTs;
   uint64_t m_pktCnt;

   InputPlugin::Result check_constraints() const;
   void swapEndpoints(Packet *pkt);
   void generatePacket(Packet *pkt);
   void generatePacketFlow1(Packet *pkt);
   void generatePacketFlowN(Packet *pkt);
};

}
#endif /* IPXP_INPUT_BENCHMARK_HPP */
