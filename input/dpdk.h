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
#include <config.h>
#ifdef WITH_DPDK

#ifndef IPXP_DPDK_READER_H
#define IPXP_DPDK_READER_H

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/utils.hpp>

#include <memory>
#include <rte_mbuf.h>
#include <sstream>

namespace ipxp {
class DpdkOptParser : public OptionsParser {
private:
    static constexpr size_t DEFAULT_MBUF_BURST_SIZE = 256;
    static constexpr size_t DEFAULT_MBUF_POOL_SIZE = 16384;
    size_t pkt_buffer_size_;
    size_t pkt_mempool_size_;
    std::uint16_t port_num_;
    uint16_t rx_queues_ = 1;
    std::string eal_;

public:
    DpdkOptParser()
        : OptionsParser("dpdk", "Input plugin for reading packets using DPDK interface")
        , pkt_buffer_size_(DEFAULT_MBUF_BURST_SIZE)
        , pkt_mempool_size_(DEFAULT_MBUF_POOL_SIZE)
    {
        register_option(
            "b",
            "bsize",
            "SIZE",
            "Size of the MBUF packet buffer. Default: " + std::to_string(DEFAULT_MBUF_BURST_SIZE),
            [this](const char* arg) {try{pkt_buffer_size_ = str2num<decltype(pkt_buffer_size_)>(arg);} catch (std::invalid_argument&){return false;} return true; },
            RequiredArgument);
        register_option(
            "p",
            "port",
            "PORT",
            "DPDK port to be used as an input interface",
            [this](const char* arg) {try{port_num_ = str2num<decltype(port_num_)>(arg);} catch (std::invalid_argument&){return false;} return true; },
            RequiredArgument);
        register_option(
            "m",
            "mem",
            "SIZE",
            "Size of the memory pool for received packets. Default: " + std::to_string(DEFAULT_MBUF_POOL_SIZE),
            [this](const char* arg) {try{pkt_mempool_size_ = str2num<decltype(pkt_mempool_size_)>(arg);} catch (std::invalid_argument&){return false;} return true; },
            RequiredArgument);
        register_option(
            "q",
            "queue",
            "COUNT",
            "Number of RX quues. Default: 1",
            [this](const char* arg) {try{rx_queues_ = str2num<decltype(rx_queues_)>(arg);} catch (std::invalid_argument&){return false;} return true; },
            RequiredArgument);
        register_option(
            "e", 
            "eal", 
            "EAL", 
            "DPDK eal", 
            [this](const char *arg){eal_ = arg; return true;}, 
            OptionFlags::RequiredArgument);
    }

    size_t pkt_buffer_size() const { return pkt_buffer_size_; }

    size_t pkt_mempool_size() const { return pkt_mempool_size_; }

    std::uint16_t port_num() const { return port_num_; }

    std::string eal_params() const { return eal_; }

    uint16_t rx_queues() const { return rx_queues_; }
};

class DpdkCore {
public:
    /**
     * @brief Configure dpdk port using user parameters
     * 
     * @param params user paramameters
     */
    void configure(const char* params);

    /**
     * @brief Get the DpdkReader Queue Id 
     * 
     * @return uint16_t rx queue id
     */
    uint16_t getRxQueueId();

    int getRxTimestampOffset();

    bool isNfbDpdkDriver();

    /**
     * @brief Start receiving on port when all lcores are ready
     * 
     */
    void startIfReady();

    void deinit();

    // ready flag
    bool is_ifc_ready;

    /**
     * @brief Get the singleton dpdk core instance
     */
    static DpdkCore& getInstance();

    DpdkOptParser parser;

    
private:
    void initInterface();
    void validatePort();
    struct rte_eth_conf createPortConfig();
    void configurePort(const struct rte_eth_conf& portConfig);
    void configureRSS();
    void registerRxTimestamp();
    void enablePort();
    std::vector<char *> convertStringToArgvFormat(const std::string& ealParams);
    void recognizeDriver();
    void configureEal(const std::string& ealParams);

    ~DpdkCore();

    uint16_t m_portId;
    uint16_t m_rxQueueCount;
    uint16_t m_txQueueCount;
    uint16_t m_currentRxId;
    int m_rxTimestampOffset;
    bool m_isNfbDpdkDriver;
    
    bool isConfigured = false;
    static DpdkCore* m_instance;
};

class DpdkReader : public InputPlugin {
public:
    Result get(PacketBlock& packets) override;

    void init(const char* params) override;

    OptionsParser* get_parser() const override
    {
        return new DpdkOptParser();
    }

    std::string get_name() const override
    {
        return "dpdk";
    }

    ~DpdkReader();
    DpdkReader();

private:
    rte_mempool* rteMempool;
    std::vector<rte_mbuf*> mbufs_;
    
    std::uint16_t pkts_read_;
    uint16_t rx_queue_id_;
    uint16_t total_queues_cnt_;

    uint16_t m_rxQueueId;
    uint16_t m_portId;
    int m_rxTimestampOffset;

    bool m_useHwRxTimestamp;

    void createRteMempool(uint16_t mempoolSize);
    void createRteMbufs(uint16_t mbufsSize);
    void setupRxQueue();
    int set_thread_affinity(uint16_t thread_id);
    struct timeval getTimestamp(rte_mbuf* mbuf);

    DpdkCore& m_dpdkCore;
};
}

#endif // IPXP_DPDK_READER_H
#endif
