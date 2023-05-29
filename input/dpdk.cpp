/**
 * \file dpdk.h
 * \brief DPDK input interface for ipfixprobe.
 * \author Roman Vrana <ivrana@fit.vutbr.cz>
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


#include <cstring>
#include <mutex>
#include <rte_ethdev.h>
#include <rte_version.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_errno.h>

#include "dpdk.h"
#include "parser.hpp"

#ifdef WITH_FLEXPROBE
#include <process/flexprobe-data.h>
#endif

#define MEMPOOL_CACHE_SIZE 256

namespace ipxp {
__attribute__((constructor)) static void register_this_plugin()
{
    static PluginRecord rec = PluginRecord("dpdk", []() { return new DpdkReader(); });
    register_plugin(&rec);
}

#ifdef WITH_FLEXPROBE
static bool convert_from_flexprobe(const rte_mbuf* mbuf, Packet& pkt)
{
    static constexpr unsigned DATA_OFFSET = 14; // size of preceeding header

    auto data_view = reinterpret_cast<const Flexprobe::FlexprobeData*>(rte_pktmbuf_mtod(mbuf, const uint8_t*) + DATA_OFFSET);

    pkt.ts = { data_view->arrival_time.sec, data_view->arrival_time.nsec / 1000 };

    std::memset(pkt.dst_mac, 0, sizeof(pkt.dst_mac));
    std::memset(pkt.src_mac, 0, sizeof(pkt.src_mac));
    pkt.ethertype = 0;

    size_t vlan_cnt = (data_view->vlan_0 ? 1 : 0) + (data_view->vlan_1 ? 1 : 0);
    size_t ip_offset = 14 + vlan_cnt * 4;

    pkt.ip_len = data_view->packet_size - ip_offset;
    pkt.ip_version = data_view->ip_version; // Get ip version
    pkt.ip_ttl = 0;
    pkt.ip_proto = data_view->l4_protocol;
    pkt.ip_tos = 0;
    pkt.ip_flags = 0;
    if (pkt.ip_version == IP::v4) {
        // IPv4 is in last 4 bytes
        pkt.src_ip.v4 = *reinterpret_cast<const uint32_t*>(data_view->src_ip.data() + 12);
        pkt.dst_ip.v4 = *reinterpret_cast<const uint32_t*>(data_view->dst_ip.data() + 12);
        pkt.ip_payload_len = pkt.ip_len - 20; // default size of IPv4 header without any options
    } else {
        std::copy(data_view->src_ip.begin(), data_view->src_ip.end(), pkt.src_ip.v6);
        std::copy(data_view->dst_ip.begin(), data_view->dst_ip.end(), pkt.dst_ip.v6);
        pkt.ip_payload_len = pkt.ip_len - 40; // size of IPv6 header without extension headers
    }

    pkt.src_port = ntohs(data_view->src_port);
    pkt.dst_port = ntohs(data_view->dst_port);
    pkt.tcp_flags = data_view->l4_flags;
    pkt.tcp_window = 0;
    pkt.tcp_options = 0;
    pkt.tcp_mss = 0;
    pkt.tcp_seq = data_view->tcp_sequence_no;
    pkt.tcp_ack = data_view->tcp_acknowledge_no;

    std::uint16_t datalen = rte_pktmbuf_pkt_len(mbuf) - DATA_OFFSET;
    pkt.packet = (uint8_t*)rte_pktmbuf_mtod(mbuf, const char*) + DATA_OFFSET;

    pkt.packet_len = 0;
    pkt.packet_len_wire = datalen;

    pkt.custom = (uint8_t*)pkt.packet;
    pkt.custom_len = datalen;

    pkt.payload = pkt.packet + data_view->size();
    pkt.payload_len = datalen < data_view->size() ? 0 : datalen - data_view->size();
    pkt.payload_len_wire = rte_pktmbuf_pkt_len(mbuf) - data_view->size();

    return true;
}
#endif

DpdkCore* DpdkCore::m_instance = nullptr;

DpdkCore& DpdkCore::getInstance()
{
    if (!m_instance) {
        m_instance = new DpdkCore();
    }
    return *m_instance;
}

DpdkCore::~DpdkCore()
{
    m_dpdkDevices.clear();
    //rte_eal_cleanup(); // segfault?
    m_instance = nullptr;
}

void DpdkCore::deinit()
{
    if (m_instance) {
        delete m_instance;
        m_instance = nullptr;
    }
}

uint16_t DpdkCore::getMbufsCount() const noexcept
{
    return m_mBufsCount;
}

void DpdkCore::configure(const char* params)
{
    if (isConfigured) {
        return;
    }

    try {
        parser.parse(params);
    } catch (ParserError& e) {
        throw PluginError(e.what());
    }

    uint16_t mempoolSize = parser.pkt_mempool_size();
    uint16_t rxQueueCount = parser.rx_queues();
    m_mBufsCount = parser.pkt_buffer_size();

    configureEal(parser.eal_params());

    m_dpdkDevices.reserve(parser.port_numbers().size());
    for (auto portID :  parser.port_numbers()) {
        m_dpdkDevices.emplace_back(portID, rxQueueCount, mempoolSize, m_mBufsCount);
    }

    isConfigured = true;
}

std::vector<char *> DpdkCore::convertStringToArgvFormat(const std::string& ealParams)
{
    // set first value as program name (argv[0])
    std::vector<char *> args = {"ipfixprobe"};
    std::istringstream iss(ealParams);
    std::string token;

    while(iss >> token) {
        char *arg = new char[token.size() + 1];
        copy(token.begin(), token.end(), arg);
        arg[token.size()] = '\0';
        args.push_back(arg);
    }
    return args;
}

void DpdkCore::configureEal(const std::string& ealParams)
{
    std::vector<char *> args = convertStringToArgvFormat(ealParams);

    if (rte_eal_init(args.size(), args.data()) < 0) {
        rte_exit(EXIT_FAILURE, "Cannot initialize RTE_EAL: %s\n", rte_strerror(rte_errno));
    }
}

uint16_t DpdkCore::getRxQueueId() noexcept
{
    return m_currentRxId++;
}

DpdkReader::DpdkReader()
    : m_dpdkCore(DpdkCore::getInstance())
{
}

DpdkReader::~DpdkReader()
{
    m_dpdkCore.deinit();
}

void DpdkReader::init(const char* params)
{
    m_dpdkCore.configure(params);
    m_rxQueueId = m_dpdkCore.getRxQueueId();
    m_dpdkDeviceCount = m_dpdkCore.getDpdkDeviceCount();
    mBufs.resize(m_dpdkCore.getMbufsCount());
}

InputPlugin::Result DpdkReader::get(PacketBlock& packets)
{
#ifndef WITH_FLEXPROBE
    parser_opt_t opt {&packets, false, false, 0};
#endif

    packets.cnt = 0;

    DpdkDevice& dpdkDevice = m_dpdkCore.getDpdkDevice(m_dpdkDeviceIndex++ % m_dpdkDeviceCount);
    uint16_t recivedPackets = dpdkDevice.receive(mBufs, m_rxQueueId);
    if (!recivedPackets) {
        return Result::TIMEOUT;
    }

    for (auto packetID = 0; packetID < recivedPackets; packetID++) {
#ifdef WITH_FLEXPROBE
        // Convert Flexprobe pre-parsed packet into IPFIXPROBE packet
        auto conv_result = convert_from_flexprobe(mBufs[packetID], packets.pkts[packets.cnt]);
        packets.bytes += packets.pkts[packets.cnt].packet_len_wire;
        m_seen++;

        if (!conv_result) {
            continue;
        }
        m_parsed++;
        packets.cnt++;
#else
        parse_packet(&opt,
            dpdkDevice.getPacketTimestamp(mBufs[packetID]),
            rte_pktmbuf_mtod(mBufs[packetID], const std::uint8_t*),
            rte_pktmbuf_data_len(mBufs[packetID]),
            rte_pktmbuf_data_len(mBufs[packetID]));
        m_seen++;
        m_parsed++;
#endif
    }

    return Result::PARSED;
}
}
