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

#include <config.h>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <cstdint>

namespace ipxp {

class alignas(64) FlowRecord
{
    uint64_t m_hash;
public:
    Flow m_flow;
#ifdef WITH_CTT
    bool is_in_ctt;                 /**< Flow is offloaded by CTT if set. */
    bool is_waiting_for_export;        /**< Export request of flow was sent to ctt,
                                                but still has not been processed in ctt. */
    timeval export_time;            /**< Time point when we sure that the export request has already been processed by ctt,
                                                and flow is not in ctt anymore. */
#endif /* WITH_CTT */

    FlowRecord();
    ~FlowRecord();

    void erase();
    void reuse();

    __attribute__((always_inline)) bool is_empty() const noexcept
    {
        return m_hash == 0;
    }

    __attribute__((always_inline)) bool belongs(uint64_t hash) const noexcept
    {
        return hash == m_hash;
    }

    void create(const Packet &pkt, uint64_t pkt_hash);
    void update(const Packet &pkt);
};

} // ipxp
