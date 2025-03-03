/**
 * \file
 * \author Pavel Siska <siska@cesnet.cz>
 * \brief Defines the FragmentationTable class for managing packet
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

#include "fragmentationTable.hpp"

#include <functional>

namespace ipxp {

FragmentationTable::FragmentationTable(std::size_t table_size)
    : m_table(table_size)
{
}

void FragmentationTable::insert(const Packet& packet)
{
    FragmentationKey key(packet);
    FragmentationData data(packet);
    auto& ring = m_table[get_table_index(key)];
    ring.push_back({ key, data });
}

FragmentationData* FragmentationTable::find(const Packet& packet) noexcept
{
    FragmentationKey key(packet);
    auto& ring = m_table[get_table_index(key)];
    auto it = std::find_if(ring.rbegin(), ring.rend(), [&](const FragmentationKeyData& entry) {
        return entry.key == key;
    });
    if (it != ring.rend()) {
        return &(it->data);
    }
    return nullptr;
}

std::size_t FragmentationTable::get_table_index(const FragmentationKey& key) const noexcept
{
    return std::hash<FragmentationKey> {}(key) % m_table.size();
}

} // namespace ipxp
