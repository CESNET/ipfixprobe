/**
 * \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief FlowKey declaration.
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

namespace ipxp {

/**
  * @brief Unique identifier for each flow - packets with the same flow key belongs to the same flow
  */ 
class alignas(16) FlowKey {
public:
   /**
     * @brief Get hash value of the key
     * @return Hash value of the key
     */
   size_t hash() const noexcept 
   {
      return XXH3_64bits(this, sizeof(*this));
   }
   
private:
   std::array<uint8_t, 16> src_ip;  // IPv4 or IPv6 source address
   std::array<uint8_t, 16> dst_ip;  // IPv4 or IPv6 destination address
   uint16_t src_port;  // Source port (0 for non-TCP/UDP protocols)
   uint16_t dst_port; // Destination port (0 for non-TCP/UDP protocols)
   uint8_t proto;  // IP protocol
   uint8_t ip_version; // IP version (4 or 6)
   uint16_t vlan_id; // VLAN ID if used, 0 otherwise 
   
friend class FlowKeyFactory; 
   
} __attribute__((packed));


} // namespace ipxp