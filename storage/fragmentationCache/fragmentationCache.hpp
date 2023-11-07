/**
 * \file
 * \author Pavel Siska <siska@cesnet.cz>
 * \brief Contains the FragmentationCache class for managing fragmented packet data using a
 * fragmentation table.
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

#pragma once

#include "fragmentationKeyData.hpp"
#include "fragmentationTable.hpp"

#include <cstdint>
#include <ipfixprobe/packet.hpp>
#include <sys/time.h>

namespace ipxp {

/**
 * @brief A class for managing fragmented packet data using a fragmentation table.
 *
 * The FragmentationCache class handles the processing and management of fragmented network packets.
 * It utilizes a fragmentation table to store and retrieve necessary data for processing fragmented
 * packets.
 *
 * The primary purpose of this class is to provide a mechanism for completing fragmented packets by
 * filling in missing port information. Fragmented packets lack port information (except first
 * fragment). Completing port information is essential for creating a complete flow key, which
 * requires the proper association of source and destination ports.
 *
 * Specifically, this class stores port information from the first fragmented packet, and when
 * subsequent fragments are received, it attempts to retrieve this port information from the
 * fragmentation table to ensure consistent port association across all fragments.
 */
class FragmentationCache {
public:
    /**
     * @brief Constructor for the FragmentationCache class.
     * @param table_size The size of the fragmentation table.
     * @param timeout_in_seconds The timeout value in seconds for fragmentation data. Default is 3
     * seconds.
     */
    FragmentationCache(std::size_t table_size, time_t timeout_in_seconds = 3);

    /**
     * @brief Processes a network packet.
     * @param packet The Packet object to be processed.
     *
     * This method handles the processing of incoming packets. If the packet is not fragmented, the
     * packet is considered complete, and no further processing is performed. If the packet is
     * fragmented, its processing is delegated to the `process_fragmented_packet` method, which
     * handles the specifics of fragmented packet handling.
     *
     * Fragmented packets require special handling to ensure complete information. If the packet is
     * the first fragment, it's inserted into the fragmentation table. For subsequent fragments,
     * missing data is retrieved from the table using the `find` method of the `FragmentationTable`
     * class. If the required data is found and hasn't timed out, it's used to fill in missing parts
     * of the packet (ports information).
     */
    void process_packet(Packet& packet);

private:
    void process_fragmented_packet(Packet& packet) noexcept;
    void fill_ports_to_packet(Packet& packet, const FragmentationData& data) const noexcept;
    void
    fill_missing_packet_data(Packet& packet, const FragmentationData& fragmentation_data) noexcept;

    bool is_fragmentation_data_timedouted(const Packet& packet, const FragmentationData& data)
        const noexcept;

    inline bool is_packet_fragmented(const Packet& packet) const noexcept
    {
        return packet.frag_off || packet.more_fragments;
    }

    inline bool is_packet_first_fragment(const Packet& packet) const noexcept
    {
        return !packet.frag_off && packet.more_fragments;
    }

    struct timeval m_timeout;
    FragmentationTable m_fragmentation_table;
};

} // namespace ipxp
