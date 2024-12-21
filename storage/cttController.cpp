//
// Created by zaida on 21.12.2024.
//

#include "cttController.hpp"

#ifdef WITH_CTT

namespace ipxp {

void CttController::init(const std::string& nfb_dev, unsigned ctt_comp_index) {
    m_commander = std::make_unique<ctt::AsyncCommander>(ctt::NfbParams{nfb_dev, ctt_comp_index});
    try {
        // Get UserInfo to determine key, state, and state_mask sizes
        ctt::UserInfo user_info = m_commander->get_user_info();
        key_size_bytes = (user_info.key_bit_width + 7) / 8;
        state_size_bytes = (user_info.state_bit_width + 7) / 8;
        state_mask_size_bytes = (user_info.state_mask_bit_width + 7) / 8;

        // Enable the CTT
        std::future<void> enable_future = m_commander->enable(true);
        enable_future.wait();
    }
    catch (const std::exception& e) {
        throw;
    }
}

void CttController::create_record(uint64_t flow_hash_ctt, const struct timeval& ts)
{
    try {
        std::vector<std::byte> key = assemble_key(flow_hash_ctt);
        std::vector<std::byte> state = assemble_state(
              OffloadMode::PACKET_OFFLOAD,
              MetaType::FULL,
              ts);
        m_commander->write_record(std::move(key), std::move(state));
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

std::vector<std::byte> CttController::assemble_key(uint64_t flow_hash_ctt)
{
    std::vector<std::byte> key(key_size_bytes, std::byte(0));
    for (size_t i = 0; i < sizeof(flow_hash_ctt) && i < key_size_bytes; ++i) {
        key[i] = static_cast<std::byte>((flow_hash_ctt >> (8 * i)) & 0xFF);
    }
    return key;
}

std::vector<std::byte> CttController::assemble_state(
    OffloadMode offload_mode, MetaType meta_type, const struct timeval& ts)
{
    std::vector<std::byte> state(state_size_bytes, std::byte(0));
    std::vector<std::byte> state_mask(state_mask_size_bytes, std::byte(0));

    state[0] = static_cast<std::byte>(offload_mode);
    state[1] = static_cast<std::byte>(meta_type);

    // timestamp in sec/ns format, 32+32 bits - 64 bits in total
    for (size_t i = 0; i < sizeof(ts.tv_sec) && i < 4; ++i) {
        state[2 + i] = static_cast<std::byte>((ts.tv_sec >> (8 * i)) & 0xFF);
    }
    for (size_t i = 0; i < sizeof(ts.tv_usec) && i < 4; ++i) {
        state[6 + i] = static_cast<std::byte>((ts.tv_usec >> (8 * i)) & 0xFF);
    }
    return state;
}

} // ipxp

#endif /* WITH_CTT */
