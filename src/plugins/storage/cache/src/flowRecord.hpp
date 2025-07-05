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

namespace ipxp {

/**
 * \brief Class representing a flow record in the cache.
 * 
 * This class contains the flow data and provides methods to create, update, and erase the flow record.
 */
class alignas(64) FlowRecord
{
    uint64_t m_hash;
public:
    Flow m_flow; ///< Flow data

    FlowRecord();

    ~FlowRecord();

    /**
     * \brief Erase the flow record data.
     * 
     * This method resets all fields of the flow record to their initial state.
     */
    maybe_virtual void erase();

    /**
     * \brief Reuse the flow record.
     * 
     * This method only resets the flow counters not erasing flow key 
     */
    void reuse();

    /**
     * \brief Create a new flow record from a packet.
     * 
     * This method initializes the flow record with data from the given packet.
     * 
     * @param pkt The packet to create the flow record from.
     * @param pkt_hash The hash of the FlowKey of the packet.
     */
    maybe_virtual void create(const Packet &pkt, uint64_t pkt_hash);

    /**
     * \brief Update the flow record with data from a packet.
     * @param pkt The packet to update the flow record with.
     */
    void update(const Packet &pkt);

    /**
     * \brief Check if flow record does not contain any valid flow.
     * @return True if the flow record is empty, false otherwise.
     */
    __attribute__((always_inline)) bool is_empty() const noexcept
    {
        return m_hash == 0;
    }

    /**
     * \brief Check if the given hash belongs to this flow record.
     * @param hash The hash to check.
     * @return True if the hash belongs to this flow record, false otherwise.
     */
    __attribute__((always_inline)) bool belongs(uint64_t hash) const noexcept
    {
        return hash == m_hash;
    }

};

} // ipxp
