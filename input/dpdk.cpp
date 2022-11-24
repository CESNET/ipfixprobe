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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
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
    rte_eth_dev_stop(m_portId);
    rte_eth_dev_close(m_portId);
    rte_eal_cleanup();
    m_instance = nullptr;
}

void DpdkCore::deinit()
{
    if (m_instance) {
        delete m_instance;
        m_instance = nullptr;
    }
}

void DpdkCore::initInterface()
{
    validatePort();
    auto portConfig = createPortConfig();
    configurePort(portConfig);
}

void DpdkCore::validatePort()
{
    if (!rte_eth_dev_is_valid_port(m_portId)) {
        throw PluginError("Invalid DPDK port specified");
    }
}

struct rte_eth_conf DpdkCore::createPortConfig()
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
    rte_eth_conf portConfig {.rxmode = {.mtu = RTE_ETHER_MAX_LEN}};
#else
    rte_eth_conf portConfig {.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}};
#endif
    portConfig.rxmode.mq_mode = ETH_MQ_RX_RSS;
    portConfig.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    return portConfig;
}

void DpdkCore::configurePort(const struct rte_eth_conf& portConfig)
{
    if (rte_eth_dev_configure(m_portId, m_rxQueueCount, m_txQueueCount, &portConfig)) {
        throw PluginError("Unable to configure interface");
    }
}

void DpdkCore::configureRSS()
{
    constexpr size_t RSS_KEY_LEN = 40;
    // biflow hash key
    static uint8_t rssKey[RSS_KEY_LEN] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
    };

    struct rte_eth_rss_conf rssConfig = {
        .rss_key = rssKey,
        .rss_key_len = RSS_KEY_LEN,
        .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
    };

    if (rte_eth_dev_rss_hash_update(m_portId, &rssConfig)) {
        throw PluginError("Unable to set RSS hash");
    }
}

void DpdkCore::enablePort()
{
    if (rte_eth_dev_start(m_portId) < 0) {
        throw PluginError("Unable to start DPDK port");
    }

    if (rte_eth_promiscuous_enable(m_portId)) {
        throw PluginError("Unable to set promiscuous mode");
    }
}

void DpdkCore::registerRxTimestamp()
{
    if (rte_mbuf_dyn_rx_timestamp_register(&m_rxTimestampOffset, NULL)) {
        throw PluginError("Unable to get Rx timestamp offset");
    }
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
   
    m_portId = parser.port_num();
    m_rxQueueCount = parser.rx_queues();
    configureEal(parser.eal_params());
    registerRxTimestamp();
    initInterface();
    recognizeDriver();
    isConfigured = true;
}

void DpdkCore::recognizeDriver()
{
    rte_eth_dev_info rteDevInfo;
    if (rte_eth_dev_info_get(m_portId, &rteDevInfo)) {
        throw PluginError("Unable to get rte dev info");
    }
    if (std::strcmp(rteDevInfo.driver_name, "net_nfb") == 0) {
        m_isNfbDpdkDriver = true;
    }
}

bool DpdkCore::isNfbDpdkDriver()
{
	return m_isNfbDpdkDriver;
}

std::vector<char *> DpdkCore::convertStringToArgvFormat(const std::string& ealParams)
{
    std::vector<char *> args;
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

uint16_t DpdkCore::getRxQueueId()
{
    return m_currentRxId++;
}

void DpdkCore::startIfReady()
{
    if (m_rxQueueCount == m_currentRxId) {
        configureRSS();
        enablePort();
        is_ifc_ready = true;
    }
}

int DpdkCore::getRxTimestampOffset()
{
    return m_rxTimestampOffset;
}

DpdkReader::DpdkReader()
    : m_dpdkCore(DpdkCore::getInstance())
{
    pkts_read_ = 0;
    m_useHwRxTimestamp = false;
}

DpdkReader::~DpdkReader()
{
    m_dpdkCore.deinit();
}

void DpdkReader::init(const char* params)
{
    m_dpdkCore.configure(params);
    m_rxQueueId = m_dpdkCore.getRxQueueId();
    m_portId = m_dpdkCore.parser.port_num();
    m_rxTimestampOffset = m_dpdkCore.getRxTimestampOffset();
    m_useHwRxTimestamp = m_dpdkCore.isNfbDpdkDriver();

    createRteMempool(m_dpdkCore.parser.pkt_mempool_size());
    createRteMbufs(m_dpdkCore.parser.pkt_buffer_size());
    setupRxQueue();   
    set_thread_affinity(m_rxQueueId);

    m_dpdkCore.startIfReady();
}

void DpdkReader::createRteMempool(uint16_t mempoolSize)
{
    std::string mpool_name = "mbuf_pool_" + std::to_string(m_rxQueueId);
    rteMempool = rte_pktmbuf_pool_create(
        mpool_name.c_str(), 
        mempoolSize, 
        MEMPOOL_CACHE_SIZE, 
        0, 
        RTE_MBUF_DEFAULT_BUF_SIZE, 
        rte_lcore_to_socket_id(m_rxQueueId));
    if (!rteMempool) {
        throw PluginError("Unable to create memory pool. " + std::string(rte_strerror(rte_errno)));
    }
}

void DpdkReader::createRteMbufs(uint16_t mbufsSize)
{
    try {
        mbufs_.resize(mbufsSize);
    } catch (const std::exception& e) {
        throw PluginError(e.what());
    }
}

void DpdkReader::setupRxQueue()
{
    int ret = rte_eth_rx_queue_setup(
        m_portId, 
        m_rxQueueId, 
        mbufs_.size(), 
        rte_eth_dev_socket_id(m_portId), 
        nullptr, 
        rteMempool);
    if (ret < 0) {
        throw PluginError("Unable to set up RX queues");
    }
}

int DpdkReader::set_thread_affinity(uint16_t thread_id)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(thread_id, &cpuset);

    return pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

struct timeval DpdkReader::getTimestamp(rte_mbuf* mbuf)
{
	struct timeval tv;
    if (m_useHwRxTimestamp) {
        static constexpr time_t nanosecInSec = 1000000000;
        static constexpr time_t nsecInUsec = 1000;
        
        rte_mbuf_timestamp_t timestamp = *RTE_MBUF_DYNFIELD(mbuf, m_rxTimestampOffset, rte_mbuf_timestamp_t *);
        tv.tv_sec = timestamp / nanosecInSec; 
        tv.tv_usec = (timestamp - ((tv.tv_sec) * nanosecInSec)) / nsecInUsec; 

        return tv;
    } else {
        auto now = std::chrono::system_clock::now();
        auto now_t = std::chrono::system_clock::to_time_t(now);

        auto dur = now - std::chrono::system_clock::from_time_t(now_t);
        auto micros = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

	    tv.tv_sec = now_t;
		tv.tv_usec = micros;
        return tv;	
    }

} 

InputPlugin::Result DpdkReader::get(PacketBlock& packets)
{
    while (m_dpdkCore.is_ifc_ready == false) {
        usleep(1000);
    }

#ifndef WITH_FLEXPROBE
    parser_opt_t opt { &packets, false, false, DLT_EN10MB };
#endif
    packets.cnt = 0;
    for (auto i = 0; i < pkts_read_; i++) {
        rte_pktmbuf_free(mbufs_[i]);
    }
    pkts_read_ = rte_eth_rx_burst(m_portId, m_rxQueueId, mbufs_.data(), mbufs_.size());
    if (pkts_read_ == 0) {
        return Result::NOT_PARSED;
    }

    for (auto i = 0; i < pkts_read_; i++) {
#ifdef WITH_FLEXPROBE
        // Convert Flexprobe pre-parsed packet into IPFIXPROBE packet
        auto conv_result = convert_from_flexprobe(mbufs_[i], packets.pkts[packets.cnt]);
        packets.bytes += packets.pkts[packets.cnt].packet_len_wire;
        m_seen++;

        if (!conv_result) {
            continue;
        }
        m_parsed++;
        packets.cnt++;
#else
        parse_packet(&opt,
            getTimestamp(mbufs_[i]),
            rte_pktmbuf_mtod(mbufs_[i], const std::uint8_t*),
            rte_pktmbuf_data_len(mbufs_[i]),
            rte_pktmbuf_data_len(mbufs_[i]));
        m_seen++;
        m_parsed++;
        packets.cnt++;
#endif
    }

    return Result::PARSED;
}
}
