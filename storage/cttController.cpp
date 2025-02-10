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
#ifdef WITH_CTT

namespace ipxp {

CttController::CttController(const std::string& nfb_dev, unsigned ctt_comp_index) {
    m_commander = std::make_unique<ctt::AsyncCommander>(ctt::NfbParams{nfb_dev, ctt_comp_index});
    try {
        // Get UserInfo to determine key, state, and state_mask sizes
        ctt::UserInfo user_info = m_commander->get_user_info();
        m_key_size_bytes = (user_info.key_bit_width + 7) / 8;
        m_state_size_bytes = (user_info.state_bit_width + 7) / 8;
        if (m_state_size_bytes != sizeof(CttState)) {
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

void CttController::create_record(const Flow& flow, uint8_t dma_channel, OffloadMode offload_mode)
{
    try {
        std::vector<std::byte> key = assemble_key(flow.flow_hash_ctt);
        std::vector<std::byte> state = assemble_state(
              offload_mode,
              MetadataType::FULL_METADATA,
              flow, dma_channel);
        m_commander->write_record(std::move(key), std::move(state));
    }
    catch (const std::exception& e) {
        throw;
    }
}

void CttController::get_state(uint64_t flow_hash_ctt)
{
    try {
        std::vector<std::byte> key = assemble_key(flow_hash_ctt);
        m_commander->export_record(std::move(key));
    }
    catch (const std::exception& e) {
        throw;
    }
}

void CttController::remove_record_without_notification(uint64_t flow_hash_ctt)
{
    try {
        std::vector<std::byte> key = assemble_key(flow_hash_ctt);
        m_commander->delete_record(std::move(key));
    }
    catch (const std::exception& e) {
        throw;
    }
}

void CttController::export_record(uint64_t flow_hash_ctt)
{
    try {
        std::vector<std::byte> key = assemble_key(flow_hash_ctt);
        m_commander->export_and_delete_record(std::move(key));
    }
    catch (const std::exception& e) {
        throw;
    }
}

std::pair<std::vector<std::byte>, std::vector<std::byte>>
CttController::get_key_and_state(uint64_t flow_hash_ctt, const Flow& flow, uint8_t dma_channel)
{
    return {assemble_key(flow_hash_ctt), assemble_state(
          OffloadMode::TRIMMED_PACKET_WITH_METADATA_AND_EXPORT,
          MetadataType::FULL_METADATA,
          flow, dma_channel)};
}

std::vector<std::byte> CttController::assemble_key(uint64_t flow_hash_ctt)
{
    return std::vector<std::byte>(reinterpret_cast<const std::byte*>(&flow_hash_ctt),
        reinterpret_cast<const std::byte*>(&flow_hash_ctt) + m_key_size_bytes);
    std::vector<std::byte> key(m_key_size_bytes, std::byte(0));
    for (size_t i = 0; i < sizeof(flow_hash_ctt) && i < m_key_size_bytes; ++i) {
        key[i] = static_cast<std::byte>((flow_hash_ctt >> (8 * i)) & 0xFF);
    }
    return key;
}

std::vector<std::byte> CttController::assemble_state(
    OffloadMode offload_mode, MetadataType meta_type, const Flow& flow, uint8_t dma_channel)
{
    std::vector<std::byte> state(sizeof(CttState), std::byte(0));
    CttState* ctt_state = reinterpret_cast<CttState*>(state.data());
    const size_t ip_length = flow.ip_version == IP::v4 ? 4 : 16;

    ctt_state->dma_channel = dma_channel;
    ctt_state->time_first.tv_sec = htole32(static_cast<uint32_t>(flow.time_first.tv_sec));
    ctt_state->time_first.tv_usec = htole32(static_cast<uint32_t>(flow.time_first.tv_usec));
    ctt_state->time_last.tv_sec = htole32(static_cast<uint32_t>(flow.time_last.tv_sec));
    ctt_state->time_last.tv_usec = htole32(static_cast<uint32_t>(flow.time_last.tv_usec));
    std::reverse_copy(reinterpret_cast<const uint8_t*>(&flow.src_ip),
        reinterpret_cast<const uint8_t*>(&flow.src_ip) + ip_length, reinterpret_cast<uint8_t*>(&ctt_state->src_ip));
    std::reverse_copy(reinterpret_cast<const uint8_t*>(&flow.dst_ip),
        reinterpret_cast<const uint8_t*>(&flow.dst_ip) + ip_length, reinterpret_cast<uint8_t*>(&ctt_state->dst_ip));
    ctt_state->ip_version = flow.ip_version == IP::v4 ? 0 : 1;
    ctt_state->ip_proto = flow.ip_proto;
    ctt_state->src_port = htole16(flow.src_port);
    ctt_state->dst_port = htole16(flow.dst_port);
    ctt_state->tcp_flags = flow.src_tcp_flags;
    ctt_state->tcp_flags_rev = flow.dst_tcp_flags;
    ctt_state->packets = htole16(flow.src_packets);
    ctt_state->packets_rev = htole16(flow.dst_packets);
    ctt_state->bytes = htole32(flow.src_bytes);
    ctt_state->bytes_rev = htole32(flow.dst_bytes);
    ctt_state->limit_size = htole16(0);
    ctt_state->offload_mode = offload_mode;
    ctt_state->meta_type = meta_type;
    ctt_state->was_exported = 0;
    return state;
}


CttController::~CttController() noexcept
{
    if (!m_commander) {
        return;
    }
    std::future<void> enable_future = m_commander->enable(false);
    enable_future.wait();
    m_commander.reset();
}

} // ipxp

#endif /* WITH_CTT */
