/**
 * \file
 * \author Pavel Siska <siska@cesnet.cz>
 * \author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * \brief Contains implementation of the FragmentationCache class for managing fragmented packet
 * data using a fragmentation table.
 *
 * The FragmentationCache class handles the processing and management of fragmented network packets.
 * It utilizes a fragmentation table to store and retrieve necessary data for processing fragmented
 * packets.
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

#include "../xxhash.h"
#include "fragmentationCache.hpp"
#include "timevalUtils.hpp"

#include <cstring>

namespace ipxp {

FragmentationCache::FragmentationCache(std::size_t table_size, time_t timeout_in_seconds)
    : m_timeout({timeout_in_seconds, 0})
    , m_fragmentation_table(table_size)
{
}

void FragmentationCache::process_packet(Packet& packet)
{
    if (!is_packet_fragmented(packet)) {
        return; // Packet is not fragmented, no further action needed.
    }
    process_fragmented_packet(packet);
}

void FragmentationCache::process_fragmented_packet(Packet& packet) noexcept
{
    if (is_packet_first_fragment(packet)) {
        m_fragmentation_table.insert(packet);
    } else {
        auto fragmentation_data = m_fragmentation_table.find(packet);
        if (fragmentation_data) {
            fill_missing_packet_data(packet, *fragmentation_data);
        }
    }
}

void FragmentationCache::fill_missing_packet_data(
    Packet& packet,
    const FragmentationData& fragmentation_data) noexcept
{
    if (!is_fragmentation_data_timedouted(packet, fragmentation_data)) {
        fill_ports_to_packet(packet, fragmentation_data);
    }
}

bool FragmentationCache::is_fragmentation_data_timedouted(
    const Packet& packet,
    const FragmentationData& data) const noexcept
{
    return packet.ts > data.timestamp + m_timeout;
}

void FragmentationCache::fill_ports_to_packet(
    Packet& packet,
    const FragmentationData& fragmentation_data) const noexcept
{
    packet.src_port = fragmentation_data.source_port;
    packet.dst_port = fragmentation_data.destination_port;
}

} // namespace ipxp
