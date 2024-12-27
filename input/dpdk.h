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
 */
 
#include <config.h>

#ifdef WITH_DPDK

#ifndef IPXP_DPDK_READER_H
#define IPXP_DPDK_READER_H

#include "dpdk/dpdkDevice.hpp"
#include "dpdk/dpdkPortTelemetry.hpp"

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/utils.hpp>

#include <memory>
#include <rte_mbuf.h>
#include <sstream>

namespace ipxp {

class DpdkOptParser : public OptionsParser {
private:
    static constexpr size_t DEFAULT_MBUF_BURST_SIZE = 64;
    static constexpr size_t DEFAULT_MBUF_POOL_SIZE = 4096;
    size_t pkt_buffer_size_;
    size_t pkt_mempool_size_;
    std::vector<uint16_t> port_numbers_;
    uint16_t rx_queues_ = 1;
    std::string eal_;
    uint16_t mtu_;

    std::vector<uint16_t> parsePortNumbers(std::string arg)
    {
        std::string delimiter = ",";

        size_t pos = 0;
        std::string token;
        while ((pos = arg.find(delimiter)) != std::string::npos) {
            std::stringstream ss;
            token = arg.substr(0, pos);
            ss << token;
            uint16_t portId;
            ss >> portId;
            port_numbers_.emplace_back(portId);
            arg.erase(0, pos + delimiter.length());
        }

        std::stringstream ss;
        ss << arg;
        uint16_t portId;
        ss >> portId;
        port_numbers_.emplace_back(portId);
        return port_numbers_;
    }

public:
    DpdkOptParser()
        : OptionsParser("dpdk", "Input plugin for reading packets using DPDK interface")
        , pkt_buffer_size_(DEFAULT_MBUF_BURST_SIZE)
        , pkt_mempool_size_(DEFAULT_MBUF_POOL_SIZE)
        , mtu_(RTE_ETHER_MAX_LEN)
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
            [this](const char* arg) {try{ port_numbers_ = parsePortNumbers(arg);} catch (std::invalid_argument&){return false;} return true; },
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
            "Number of RX queues. Default: 1",
            [this](const char* arg) {try{rx_queues_ = str2num<decltype(rx_queues_)>(arg);} catch (std::invalid_argument&){return false;} return true; },
            RequiredArgument);
        register_option(
            "e", 
            "eal", 
            "EAL", 
            "DPDK eal", 
            [this](const char *arg){eal_ = arg; return true;}, 
            OptionFlags::RequiredArgument);
        register_option(
            "M",
            "mtu",
            "MTU",
            "Input interface MTU. Default: " + std::to_string(RTE_ETHER_MAX_LEN),
            [this](const char *arg) {try{mtu_ = str2num<decltype(mtu_)>(arg);} catch (std::invalid_argument&){return false;} return true; },
            RequiredArgument);
    }

    size_t pkt_buffer_size() const { return pkt_buffer_size_; }

    size_t pkt_mempool_size() const { return pkt_mempool_size_; }

    std::vector<uint16_t> port_numbers() const { return port_numbers_; }

    std::string eal_params() const { return eal_; }

    uint16_t rx_queues() const { return rx_queues_; }

    uint16_t mtu_size() const { return mtu_; }
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
    uint16_t getRxQueueId() noexcept;

    /**
     * @brief Get the  Mbufs count to use
     * 
     * @return uint16_t Mbufs count
     */
    uint16_t getMbufsCount() const noexcept;

    void deinit();

    /**
     * @brief Get the singleton dpdk core instance
     */
    static DpdkCore& getInstance();

    DpdkOptParser parser;

    DpdkDevice& getDpdkDevice(size_t deviceIndex)
    {
        return m_dpdkDevices[deviceIndex];
    }

    size_t getDpdkDeviceCount() const noexcept
    {
        return m_dpdkDevices.size();
    }
    
private:
    std::vector<char *> convertStringToArgvFormat(const std::string& ealParams);
    void configureEal(const std::string& ealParams);

    ~DpdkCore();

    std::vector<DpdkDevice> m_dpdkDevices;
    std::vector<uint16_t> m_portIds;
    uint16_t m_mBufsCount = 0;
    uint16_t m_currentRxId = 0;
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

    void configure_telemetry_dirs(
        std::shared_ptr<telemetry::Directory> plugin_dir, 
        std::shared_ptr<telemetry::Directory> queues_dir) override;

private:

    telemetry::Content get_queue_telemetry();
    telemetry::Content get_port_telemetry(uint16_t portNumber);

    std::vector<DpdkPortTelemetry> m_portsTelemetry;

    struct DpdkRxStats {
        uint64_t receivedPackets;
        uint64_t receivedBytes;
    };

    size_t m_dpdkDeviceCount;
    uint64_t m_dpdkDeviceIndex = 0;
    uint16_t m_rxQueueId;
    DpdkCore& m_dpdkCore;
    DpdkMbuf mBufs;
    DpdkRxStats m_stats = {};
};

}

#endif // IPXP_DPDK_READER_H
#endif
