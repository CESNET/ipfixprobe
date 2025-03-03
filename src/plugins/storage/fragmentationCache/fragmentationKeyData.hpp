/**
 * \file
 * \author Pavel Siska <siska@cesnet.cz>
 * \brief Defines classes and structures for managing packet fragmentation data.
 *
 * This file contains the declarations of the `FragmentationKey`, `FragmentationData`,
 * and `FragmentationKeyData` structures, along with a specialization of the
 * `std::hash` template for the `FragmentationKey` structure. These structures
 * are used for managing fragmented packet information and their associated data.
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

#include "../xxhash.h"

#include <cstring>
#include <ctime>
#include <functional>
#include <ipfixprobe/ipaddr.hpp>
#include <ipfixprobe/packet.hpp>

namespace ipxp {

/**
 * @brief A struct representing a key for identifying fragmented packets.
 *
 * This struct is used to create keys for identifying fragmented packets based on
 * their source IP, destination IP, fragmentation ID, and VLAN ID.
 */
struct FragmentationKey {
    /**
     * @brief Constructs a FragmentationKey object from a Packet structure.
     *
     * @param packet The Packet object from which to construct the key.
     */
    FragmentationKey(const Packet& packet)
        : ip_version(packet.ip_version)
        , source_ip(packet.src_ip)
        , destination_ip(packet.dst_ip)
        , fragmentation_id(packet.frag_id)
        , vlan_id(packet.vlan_id)
    {
    }

    FragmentationKey() = default;

    bool operator==(const FragmentationKey& other) const
    {
        if (std::memcmp(this, &other, sizeof(FragmentationKey)) == 0) {
            return true;
        }
        return false;
    }

    uint16_t ip_version; ///< ipv4 or ipv6
    ipaddr_t source_ip; ///< Source IP address of the packet.
    ipaddr_t destination_ip; ///< Destination IP address of the packet.
    uint32_t fragmentation_id; ///< Fragmentation ID of the packet.
    uint16_t vlan_id; ///< VLAN ID of the packet.
} __attribute__((packed));

/**
 * @brief A struct representing fragmentation data associated with a packet.
 */
struct FragmentationData {
    /**
     * @brief Constructs a FragmentationData object from a Packet structure.
     *
     * @param packet The Packet object from which to construct the data.
     */
    FragmentationData(const Packet& packet)
        : source_port(packet.src_port)
        , destination_port(packet.dst_port)
        , timestamp(packet.ts)
    {
    }

    FragmentationData() = default;

    uint16_t source_port; ///< Source port of the packet.
    uint16_t destination_port; ///< Destination port of the packet.
    timeval timestamp; ///< Timestamp of the packet.
};

/**
 * @brief A struct combining a FragmentationKey with its associated FragmentationData.
 */
struct FragmentationKeyData {
    FragmentationKey key;
    FragmentationData data;
};

} // namespace ipxp

namespace std {

/**
 * @brief Specialization of the std::hash template for FragmentationKey.
 *
 * This specialization enables using FragmentationKey objects as keys in hash-based containers.
 */
template<>
struct hash<ipxp::FragmentationKey> {
    /**
     * @brief Calculates the hash value for a FragmentationKey object.
     *
     * @param fragmentationKey The FragmentationKey object to hash.
     * @return The calculated hash value.
     */
    std::size_t operator()(const ipxp::FragmentationKey& fragmentation_key) const
    {
        return XXH64(
            reinterpret_cast<const void*>(&fragmentation_key),
            sizeof(fragmentation_key),
            0);
    }
};

} // namespace std
