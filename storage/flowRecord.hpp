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
    bool is_in_ctt;                 /**< Flow is ofloaded by CTT if set. */
    bool is_waiting_for_export;        /**< Flow cant be exported if set. */
    timeval export_time;            /**< Time until the export of the flow is delayed. */
#endif /* WITH_CTT */

    FlowRecord();
    ~FlowRecord();

    void erase();
    void reuse();

    bool is_empty() const noexcept;
    bool belongs(uint64_t pkt_hash) const noexcept;
    void create(const Packet &pkt, uint64_t pkt_hash);
    void update(const Packet &pkt);
};

} // ipxp
