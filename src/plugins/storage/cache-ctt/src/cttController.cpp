/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief CttController implementation.
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
 */

#include "cttController.hpp"
#include <cstring>
#include <endian.h>
#include <iostream>
#include <ctt_card.hpp>

namespace ipxp {

CttController::CttController(const std::string& nfb_dev, unsigned ctt_comp_index) {
    ctt::Card<KEY_SIZE, STATE_SIZE, MASK_SIZE> card(nfb_dev);   
    m_commander = card.get_async_commander(ctt_comp_index, std::nullopt, CttController::LIBCTT_QUEUE_SIZE);
    try {
        // Get UserInfo to determine key, state, and state_mask sizes
        ctt::UserInfo user_info = m_commander->get_user_info();
        m_key_size_bytes = (user_info.key_bit_width + 7) / 8;
        m_state_size_bytes = (user_info.state_bit_width + 7) / 8;
        if (m_state_size_bytes != sizeof(feta::CttRecord)) {
            throw std::runtime_error("Size of CTT state does not match the expected size.");
        }
        m_state_mask_size_bytes = (user_info.state_mask_bit_width + 7) / 8;

        // Enable the CTT
        std::future<void> enable_future = m_commander->enable(true);
        enable_future.wait();
    }
    catch (const std::exception& e) {
        throw;
    }
}

size_t CttController::get_approximate_queue_size()
{
    return m_commander->get_queue_size_approx();
}

const CttController::RequestStats& CttController::get_request_stats() const noexcept
{
    return m_stats;
};

template<typename Callable>
void try_with_sleep(Callable&& callable) noexcept
{
    bool success = false;
    while (!success) {
        try {
            callable();
            success = true;
        } catch (const ctt::CttException& e) {
            sleep(1);
        }
    }
}

void CttController::create_record(const Flow& flow, uint8_t dma_channel, feta::OffloadMode offload_mode)
{
    std::array<std::byte, KEY_SIZE> key = assemble_key(flow.flow_hash_ctt);
    std::array<std::byte, sizeof(feta::CttRecord)> state = assemble_state(
            offload_mode,
            feta::MetaType::FULL_META,
            flow, dma_channel);
    try_with_sleep([&]() {
        m_stats.create_record_requests++;
        m_commander->export_and_write_record(std::move(key), std::move(state));
    });
}

void CttController::get_state(uint64_t flow_hash_ctt)
{
    std::array<std::byte, KEY_SIZE> key = assemble_key(flow_hash_ctt);
    try_with_sleep([&]() {
        m_commander->export_record(std::move(key));
    });
}

void CttController::remove_record_without_notification(uint64_t flow_hash_ctt)
{
    std::array<std::byte, KEY_SIZE> key = assemble_key(flow_hash_ctt);
    try_with_sleep([&]() {
        m_commander->delete_record(std::move(key));
    });
}

void CttController::export_record(uint64_t flow_hash_ctt)
{
    std::array<std::byte, KEY_SIZE> key = assemble_key(flow_hash_ctt);
    try_with_sleep([&]() {
        m_stats.export_and_delete_requests++;
        m_commander->export_and_delete_record(std::move(key));
    });
}

std::array<std::byte, KEY_SIZE> CttController::assemble_key(uint64_t flow_hash_ctt)
{
    std::array<std::byte, KEY_SIZE> key;
    std::memcpy(key.data(), &flow_hash_ctt, KEY_SIZE);
    return key;
}

std::array<std::byte, sizeof(feta::CttRecord)> CttController::assemble_state(
    feta::OffloadMode offload_mode, feta::MetaType meta_type, const Flow& flow, uint8_t dma_channel)
{
    std::array<std::byte, sizeof(feta::CttRecord)> state;
    std::memset(state.data(), 0, sizeof(feta::CttRecord));
    feta::CttRecord record;
    record.ts_first.time_sec = flow.time_first.tv_sec;
    record.ts_first.time_ns = flow.time_first.tv_usec * 1000;
    record.ts_last.time_sec = flow.time_last.tv_sec;
    record.ts_last.time_ns = flow.time_last.tv_usec * 1000;
    const size_t ip_length = flow.ip_version == IP::v4 ? 4 : 16;
    std::memset(record.ip_src.data(), 0, 16);
    std::memset(record.ip_dst.data(), 0, 16);
    std::memcpy(record.ip_src.data(), &flow.src_ip, ip_length);
    std::memcpy(record.ip_dst.data(), &flow.dst_ip, ip_length);
    record.port_src = flow.src_port;
    record.port_dst = flow.dst_port;
    record.vlan_tci = flow.vlan_id;
    record.l4_proto = flow.ip_proto;
    record.ip_ver = flow.ip_version == IP::v4 ? feta::IpVersion::IPV4 : feta::IpVersion::IPV6;
    record.vlan_vld = flow.vlan_id ? 1 : 0;
    record.offload_mode = offload_mode;
    record.meta_type = meta_type;
    record.limit_size = 0;
    record.dma_chan = dma_channel;
    record.bytes = 0;
    record.bytes_rev = 0;
    record.pkts = 0;
    record.pkts_rev = 0;
    record.tcp_flags = 0;
    record.tcp_flags_rev = 0;
    feta::CttRecord::serialize(record, state.data());
    return state;
}

ctt::CommanderStats<size_t> CttController::get_queue_stats() const noexcept
{
    return m_commander->get_stats_global();
}

CttController::~CttController() noexcept
{
    /*if (!m_commander) {
        return;
    }
    std::future<void> enable_future = m_commander->enable(false);
    enable_future.wait();
    m_commander.reset();*/
}

} // ipxp
