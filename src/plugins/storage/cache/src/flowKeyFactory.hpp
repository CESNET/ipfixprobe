/**
 * \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief FlowKey factory. Create FlowKey objects from packet data
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

#include <cstdint>
#include <cstddef>
#include <array>
#include <variant>
#include <optional>

#include "flowKey.hpp"

namespace ipxp {

/**
 * \brief Factory class for creating FlowKey objects.
 * 
 * This class provides static methods to create FlowKey objects based on
 * source and destination IP addresses, ports, protocol, IP version, and VLAN ID.
 */
class FlowKeyFactory {
public:
   static constexpr size_t EMPTY_VLAN = 0;

   /**
    * \brief Create a direct FlowKey object with the given parameters. Keeps given ip addresses and ports directions
    * 
    * @param src_ip Pointer to the source IP address (IPv4 or IPv6).
    * @param dst_ip Pointer to the destination IP address (IPv4 or IPv6).
    * @param src_port Source port (0 for non-TCP/UDP protocols).
    * @param dst_port Destination port (0 for non-TCP/UDP protocols).
    * @param proto IP protocol.
    * @param ip_version IP version (IPv4 or IPv6).
    * @param vlan_id VLAN ID (EMPTY_VLAN if not used).
    * @return A FlowKey object initialized with the provided parameters.
    */
   template<typename Int>
   static FlowKey
   create_direct_key(const Int* src_ip, const Int* dst_ip,
      uint16_t src_port, uint16_t dst_port, uint8_t proto, IP ip_version, uint16_t vlan_id) noexcept
   {
      FlowKey res{};
      // IPv4 to IPv6 mapping
      if (ip_version == IP::v4) {   
         *reinterpret_cast<uint64_t*>(&res.src_ip[0]) = 0;
         *reinterpret_cast<uint32_t*>(&res.src_ip[8]) = htobe32(0x0000FFFF);
         *reinterpret_cast<uint32_t*>(&res.src_ip[12]) = *reinterpret_cast<const uint32_t*>(src_ip);
         *reinterpret_cast<uint64_t*>(&res.dst_ip[0]) = 0;
         *reinterpret_cast<uint32_t*>(&res.dst_ip[8]) = htobe32(0x0000FFFF);
         *reinterpret_cast<uint32_t*>(&res.dst_ip[12]) = *reinterpret_cast<const uint32_t*>(dst_ip);
      } else if (ip_version == IP::v6) {
         std::memcpy(res.src_ip.begin(), src_ip, 16);
         std::memcpy(res.dst_ip.begin(), dst_ip, 16);
      }
      res.src_port = src_port;
      res.dst_port = dst_port;
      res.proto = proto;
      res.ip_version = ip_version;
      res.vlan_id = vlan_id;
      return res;
   }

   /**
    * \brief Create a reversed FlowKey object with the given parameters. Reverses ip addresses and ports directions
    * 
    * @param src_ip Pointer to the source IP address (IPv4 or IPv6).
    * @param dst_ip Pointer to the destination IP address (IPv4 or IPv6).
    * @param src_port Source port (0 for non-TCP/UDP protocols).
    * @param dst_port Destination port (0 for non-TCP/UDP protocols).
    * @param proto IP protocol.
    * @param ip_version IP version (IPv4 or IPv6).
    * @param vlan_id VLAN ID (EMPTY_VLAN if not used).
    * @return A FlowKey object initialized with the provided parameters, with reversed IP addresses and ports.
    */
   template<typename Int>
   static FlowKey
   create_reversed_key(const Int* src_ip, const Int* dst_ip,
      uint16_t src_port, uint16_t dst_port, uint8_t proto, IP ip_version, uint16_t vlan_id) noexcept
   {
      return create_direct_key(dst_ip, src_ip, dst_port, src_port, proto, ip_version, vlan_id);
   }

   /**
    * \brief Create a sorted FlowKey object based on source and destination IP addresses and ports.
    * 
    * Flow to which packet belongs can be found only with one search.
    * 
    * @param src_ip Pointer to the source IP address (IPv4 or IPv6).
    * @param dst_ip Pointer to the destination IP address (IPv4 or IPv6).
    * @param src_port Source port (0 for non-TCP/UDP protocols).
    * @param dst_port Destination port (0 for non-TCP/UDP protocols).
    * @param proto IP protocol.
    * @param ip_version IP version (IPv4 or IPv6).
    * @param vlan_id VLAN ID (EMPTY_VLAN if not used).
    * @return A pair containing the FlowKey and a boolean indicating if it was created in reversed order.
    */
   template<typename Int>
   static std::pair<FlowKey, bool>
   create_sorted_key(const Int* src_ip, const Int* dst_ip,
      uint16_t src_port, uint16_t dst_port, uint8_t proto, IP ip_version, uint16_t vlan_id) noexcept
   {
      if (src_port < dst_port || (src_port == dst_port && std::memcmp(src_ip, dst_ip, ip_version == IP::v4 ? 4 : 16) < 0)) {
         return {create_direct_key(src_ip, dst_ip, src_port, dst_port, proto, ip_version, vlan_id), false};
      }
      return {create_reversed_key(src_ip, dst_ip, src_port, dst_port, proto, ip_version, vlan_id), true};
   }
};

} // ipxp