/**
 * \file dpdk-ring.h
 * \brief DPDK ring input interface for ipfixprobe (secondary DPDK app).
 * \author Jaroslav Pesek <pesek@cesnet.cz>
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
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
 */
#include <config.h>
#ifdef WITH_DPDK

#ifndef IPXP_DPDK_RING_READER_H
#define IPXP_DPDK_RING_READER_H

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/utils.hpp>

#include <memory>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <sstream>

namespace ipxp {
class DpdkRingOptParser : public OptionsParser {
private:
    static constexpr size_t DEFAULT_MBUF_BURST_SIZE = 256;
    size_t pkt_buffer_size_;

    std::string ring_name_;
    std::string eal_;
public:
    DpdkRingOptParser()
        : OptionsParser("dpdk-ring", "DPDK ring input interface for ipfixprobe (secondary DPDK app).")
        , pkt_buffer_size_(DEFAULT_MBUF_BURST_SIZE)
    {
        register_option(
            "b",
            "bsize",
            "SIZE",
            "Size of the MBUF packet buffer. Default: " + std::to_string(DEFAULT_MBUF_BURST_SIZE),
            [this](const char* arg) {try{pkt_buffer_size_ = str2num<decltype(pkt_buffer_size_)>(arg);} catch (std::invalid_argument&){return false;} return true; },
            RequiredArgument);
        register_option(
            "r",
            "ring",
            "RING",
            "Name of the ring to read packets from. Need to be specified explicitly thus no default provided.",
            [this](const char* arg) {ring_name_ = arg; return true;},
            OptionFlags::RequiredArgument);
        register_option(
            "e", 
            "eal", 
            "EAL", 
            "DPDK eal", 
            [this](const char *arg){eal_ = arg; return true;}, 
            OptionFlags::RequiredArgument);

    }
    size_t pkt_buffer_size() const { return pkt_buffer_size_; }

    std::string ring_name() const { return ring_name_; }

    std::string eal_params() const { return eal_; }
};

class DpdkRingCore {
public:
    /**
     * @brief Configure DPDK secondary process.
     * 
     * @param eal_params DPDK EAL parameters.
    */
   void configure(const char *params);

    /**
     * @brief Get the singleton dpdk core instance
     */
    static DpdkRingCore &getInstance();
    void deinit();

    DpdkRingOptParser parser;

private:
    std::vector<char *> convertStringToArgvFormat(const std::string &ealParams);
    void configureEal(const std::string &ealParams);
    ~DpdkRingCore();
    bool isConfigured = false;
    static DpdkRingCore *m_instance;
};

class DpdkRingReader : public InputPlugin {
public:
    Result get(PacketBlock &packets) override;

    void init(const char* params) override;

    OptionsParser* get_parser() const override
    {
        return new DpdkRingOptParser();
    }

    std::string get_name() const override
    {
        return "dpdk-ring";
    }

    ~DpdkRingReader();
    DpdkRingReader();
private:
    std::vector<rte_mbuf *> mbufs_;
    std::uint16_t pkts_read_;

    void createRteMbufs(uint16_t mbufsSize);
    struct timeval getTimestamp(rte_mbuf *mbuf);
    DpdkRingCore &m_dpdkRingCore;
    rte_ring *m_ring;
    bool is_reader_ready = false;


};
} // namespace ipxp

#endif // IPXP_DPDK_RING_READER_H
#endif
