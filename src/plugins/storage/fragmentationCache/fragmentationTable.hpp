/**
 * \file
 * \author Pavel Siska <siska@cesnet.cz>
 * \brief Declares the FragmentationTable class for managing packet
 *        fragmentation data using ring buffers.
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

#include "fragmentationKeyData.hpp"
#include "ringBuffer.hpp"

#include <cstdint>
#include <ipfixprobe/packet.hpp>
#include <vector>

namespace ipxp {

/**
 * @class FragmentationTable
 * @brief Manages packet fragmentation data using ring buffers.
 *
 * The FragmentationTable class provides a mechanism for storing and retrieving
 * packet fragmentation data using ring buffers. It allows efficient insertion
 * and retrieval of data associated with packet fragments based on their keys.
 */
class FragmentationTable {
public:
    /**
     * @brief Constructs a FragmentationTable with a specified size.
     * @param table_size The number of ring buffers in the table.
     */
    explicit FragmentationTable(std::size_t table_size);

    /**
     * @brief Inserts packet fragmentation data into the table.
     * @param packet The packet containing the data to insert.
     */
    void insert(const Packet& packet);

    /**
     * @brief Finds packet fragmentation data based on a packet.
     * @param packet The packet to search for in the table.
     * @return A pointer to the associated FragmentationData if found, or nullptr if not found.
     */
    FragmentationData* find(const Packet& packet) noexcept;

private:
    std::size_t get_table_index(const FragmentationKey& key) const noexcept;

    static constexpr std::size_t RING_SIZE = 4;
    std::vector<RingBuffer<FragmentationKeyData, RING_SIZE>> m_table;
};

} // namespace ipxp
