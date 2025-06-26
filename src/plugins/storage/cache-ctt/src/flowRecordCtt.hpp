/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief FlowRecord declaration.
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

#pragma once

#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <cstdint>
#include <optional>
#include <ipfixprobe/cttmeta.hpp>

#include "../../cache/src/flowRecord.hpp"

namespace ipxp {

struct alignas(64) FlowRecordCtt : public FlowRecord 
{
    bool can_be_offloaded;  /**< No flow collision in CTT */
    std::optional<timeval> last_request_time; /**< Time point when the last not processed request was sent to CTT. */
    std::optional<feta::OffloadMode> offload_mode; /**< Offload mode of the flow. Nullopt if not offloaded*/

    void erase() override;

    void create(const Packet &pkt, uint64_t pkt_hash) override;

    __attribute__((always_inline)) bool is_in_ctt() const noexcept
    {
        return offload_mode.has_value();
    }

    __attribute__((always_inline)) bool is_waiting_ctt_response() const noexcept
    {
        return is_in_ctt() && last_request_time.has_value();
    }

};

} // ipxp
