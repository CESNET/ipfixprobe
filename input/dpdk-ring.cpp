/**
 * \file dpdk-ring.cpp
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
#include <cstring>
#include <mutex>
#include <rte_ethdev.h>
#include <rte_version.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_errno.h>

#include "dpdk-ring.h"
#include "parser.hpp"

namespace ipxp {
__attribute__((constructor)) static void register_this_plugin()
{
    static PluginRecord rec = PluginRecord("dpdk-ring", []() { return new DpdkRingReader(); });
    register_plugin(&rec);
}

DpdkRingCore *DpdkRingCore::m_instance = nullptr;

DpdkRingCore &DpdkRingCore::getInstance()
{
    if (!m_instance) {
        m_instance = new DpdkRingCore();
    }
    return *m_instance;
}

DpdkRingCore::~DpdkRingCore()
{
    rte_eal_cleanup();
    m_instance = nullptr;
}

void DpdkRingCore::deinit()
{
    if (m_instance) {
        delete m_instance;
        m_instance = nullptr;
    }
}

void DpdkRingCore::configure(const char* params) {
    if (isConfigured) {
        return;
    }

    try {
        parser.parse(params);
    } catch (ParserError& e) {
        throw PluginError(e.what());
    }

    configureEal(parser.eal_params());
    isConfigured = true;
}

std::vector<char *> DpdkRingCore::convertStringToArgvFormat(const std::string& ealParams)
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

void DpdkRingCore::configureEal(const std::string& ealParams)
{
    std::vector<char *> args = convertStringToArgvFormat(ealParams);

    if (rte_eal_init(args.size(), args.data()) < 0) {
        rte_exit(EXIT_FAILURE, "Cannot initialize RTE_EAL: %s\n", rte_strerror(rte_errno));
    }
}

DpdkRingReader::DpdkRingReader()
    : m_dpdkRingCore(DpdkRingCore::getInstance())
{
    pkts_read_ = 0;
}

DpdkRingReader::~DpdkRingReader()
{
    m_dpdkRingCore.deinit();
}

void DpdkRingReader::createRteMbufs(uint16_t mbufsSize)
{
    try {
        mbufs_.resize(mbufsSize);
    } catch (const std::exception& e) {
        throw PluginError(e.what());
    }
}

void DpdkRingReader::init(const char* params)
{
    m_dpdkRingCore.configure(params);
    DpdkRingOptParser parser;
    try {
        parser.parse(params);
    } catch (ParserError& e) {
        throw PluginError(e.what());
    }
    createRteMbufs(m_dpdkRingCore.parser.pkt_buffer_size());
    m_ring = rte_ring_lookup(parser.ring_name().c_str());
    if (!m_ring) {
        throw PluginError("Cannot find ring with name: " + parser.ring_name());
    } else {
        is_reader_ready = true;
    }
}

struct timeval DpdkRingReader::getTimestamp(rte_mbuf* mbuf)
{
    struct timeval tv;
    auto now = std::chrono::system_clock::now();
    auto now_t = std::chrono::system_clock::to_time_t(now);

    auto dur = now - std::chrono::system_clock::from_time_t(now_t);
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

    tv.tv_sec = now_t;
    tv.tv_usec = micros;
    return tv;
}

InputPlugin::Result DpdkRingReader::get(PacketBlock& packets) 
{
    while (is_reader_ready == false) {
        usleep(1000);
    }

    parser_opt_t opt {&packets, false, false, 0};

    packets.cnt = 0;
    for (auto i = 0; i < pkts_read_; i++) {
        rte_pktmbuf_free(mbufs_[i]);
    }
    pkts_read_ = rte_ring_dequeue_burst(
        m_ring,
        reinterpret_cast<void**>(mbufs_.data()),
        mbufs_.capacity(),
        nullptr);
    if (pkts_read_ == 0) {
        return Result::TIMEOUT;
    }
    for (auto i = 0; i < pkts_read_; i++) {
        parse_packet(&opt,
            getTimestamp(mbufs_[i]),
            rte_pktmbuf_mtod(mbufs_[i], const std::uint8_t*),
            rte_pktmbuf_data_len(mbufs_[i]),
            rte_pktmbuf_data_len(mbufs_[i]));
        m_seen++;
        m_parsed++;
    }
    return Result::PARSED;
}
} // namespace ipxp