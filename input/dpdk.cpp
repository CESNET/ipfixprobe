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

#include "dpdk.h"
#include "parser.hpp"

#ifdef WITH_FLEXPROBE
#include <process/flexprobe-data.h>
#endif

namespace ipxp
{
    __attribute__((constructor)) static void register_this_plugin()
    {
        static PluginRecord rec = PluginRecord("dpdk", [](){return new DpdkReader();});
        register_plugin(&rec);
    }

#ifdef WITH_FLEXPROBE
    static bool convert_from_flexprobe(const rte_mbuf* mbuf, Packet& pkt)
    {
        static constexpr unsigned DATA_OFFSET = 14; // size of preceeding header

        auto data_view = reinterpret_cast<const Flexprobe::FlexprobeData*>(rte_pktmbuf_mtod(mbuf, const uint8_t*) + DATA_OFFSET);

        pkt.ts = {data_view->arrival_time.sec, data_view->arrival_time.nsec / 1000};

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
        pkt.packet = (uint8_t *)rte_pktmbuf_mtod(mbuf, const char*) + DATA_OFFSET;

        pkt.packet_len = 0;
        pkt.packet_len_wire = datalen;

        pkt.custom = (uint8_t *)pkt.packet;
        pkt.custom_len = datalen;

        pkt.payload = pkt.packet + data_view->size();
        pkt.payload_len = datalen < data_view->size() ? 0 : datalen - data_view->size();
        pkt.payload_len_wire = rte_pktmbuf_pkt_len(mbuf) - data_view->size();

        return true;
    }
#endif

    bool DpdkReader::is_ifc_ready = false;

    DpdkReader::DpdkReader()
    {
        pkts_read_ = 0;
        mpool_ = nullptr;
    }

    DpdkReader::~DpdkReader()
    {
        /*
        rte_mempool_free(mpool_);
        if (total_queues_cnt_ - 1 == rx_queue_id_) {
            rte_eth_dev_stop(port_id_);
            rte_eth_dev_close(port_id_);
        }
        */
    }

    void DpdkReader::global_init(uint16_t port_id, uint16_t nb_rx_queue)
    {
#if RTE_VERSION >= RTE_VERSION_NUM(21,11,0,0)
        rte_eth_conf port_conf{.rxmode = {.mq_mode = ETH_MQ_RX_RSS, .mtu = RTE_ETHER_MAX_LEN}};
#else
        rte_eth_conf port_conf{.rxmode = {.mq_mode = ETH_MQ_RX_RSS, .max_rx_pkt_len = RTE_ETHER_MAX_LEN}};
#endif

        if (!rte_eth_dev_is_valid_port(port_id)) {
            throw PluginError("Invalid DPDK port specified");
        }

        if (rte_eth_dev_configure(port_id, nb_rx_queue, 0, &port_conf) != 0) {
            throw PluginError("Unable to configure interface");
        }
    }

    void DpdkReader::set_rss_hash(uint16_t port_id)
    {
        constexpr size_t RSS_KEY_LEN = 40;
        // biflow hash key
        static uint8_t rss_key[RSS_KEY_LEN] = { 
            0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 
            0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 
            0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 
            0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
        };

        struct rte_eth_rss_conf rss_conf = {
            .rss_key = rss_key,
            .rss_key_len = RSS_KEY_LEN,
            .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
        };

        int ret = rte_eth_dev_rss_hash_update(port_id, &rss_conf);
        if (ret) {
            throw PluginError("Unable to set RSS hash");
        }
    }

    void DpdkReader::global_post_init(uint16_t port_id)
    {
        set_rss_hash(port_id);

        if (rte_eth_dev_start(port_id) < 0) {
            throw PluginError("Unable to start DPDK port");
        }

        rte_eth_promiscuous_enable(port_id);
        is_ifc_ready = true;
    }

    void DpdkReader::init(const char *params)
    {
        std::string mpool_name;
        DpdkOptParser parser;

        try {
            parser.parse(params);
        } catch (ParserError& e) {
            throw PluginError(e.what());
        }

        port_id_ = parser.port_num();
        rx_queue_id_ = parser.id();
        total_queues_cnt_ = parser.rx_queues();

        if (rx_queue_id_ == 0) {
            global_init(port_id_, parser.rx_queues());
        }

        mpool_name = "mbuf_pool_" + std::to_string(parser.id());
        mpool_ = rte_pktmbuf_pool_create(mpool_name.c_str(), parser.pkt_mempool_size(), 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(parser.id()));
        if (!mpool_) {
            throw PluginError("Unable to create memory pool. " + std::string(rte_strerror(rte_errno)));
        }

        try {
            mbufs_.resize(parser.pkt_buffer_size());
        } catch (const std::exception& e) {
            throw PluginError(e.what());
        }

        if (rte_eth_rx_queue_setup(port_id_, parser.id(), mbufs_.size(), rte_eth_dev_socket_id(port_id_), nullptr, mpool_) < 0) {
            throw PluginError("Unable to set up RX queues");
        }

        set_thread_affinity(parser.id());

        if (parser.rx_queues() - 1 == rx_queue_id_) {
            global_post_init(port_id_);
        }
    }

    int DpdkReader::set_thread_affinity(uint16_t thread_id)
    {
        cpu_set_t cpuset;

        CPU_ZERO(&cpuset);
        CPU_SET(thread_id, &cpuset);

        return pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    InputPlugin::Result DpdkReader::get(PacketBlock& packets)
    {
        while (is_ifc_ready == false) {
            usleep(1000);
        }

#ifndef WITH_FLEXPROBE
        parser_opt_t opt{&packets, false, false, DLT_EN10MB};
#endif
        packets.cnt = 0;
        for (auto i = 0; i < pkts_read_; i++) {
            rte_pktmbuf_free(mbufs_[i]);
        }
        pkts_read_ = rte_eth_rx_burst(port_id_, rx_queue_id_, mbufs_.data(), mbufs_.size());
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
                         timeval(),
                         rte_pktmbuf_mtod(mbufs_[i], const std::uint8_t *),
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