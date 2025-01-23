/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief FlowKey structure declaration.
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

template<size_t AddressSize>
struct FlowKey {
   uint16_t src_port;
   uint16_t dst_port;
   uint8_t proto;
   uint8_t ip_version;
   std::array<uint8_t, AddressSize> src_ip;
   std::array<uint8_t, AddressSize> dst_ip;
   uint16_t vlan_id;
protected:
  void save_direct(const Packet& packet) noexcept
  {
    src_port = packet.src_port;
    dst_port = packet.dst_port;
    proto = packet.ip_proto;
    ip_version = packet.ip_version;
    vlan_id = packet.vlan_id;
  }

  void save_reversed(const Packet& packet) noexcept
  {
    save_direct(packet);
    src_port = packet.dst_port;
    dst_port = packet.src_port;
  }

} __attribute__((packed));

struct FlowKeyv4 : FlowKey<4> {

  static FlowKeyv4 save_direct(const Packet& packet) noexcept
  {
    FlowKeyv4 res;
    res.FlowKey::save_direct(packet);
    std::memcpy(res.src_ip.data(), &packet.src_ip.v4, 4);
    std::memcpy(res.dst_ip.data(), &packet.dst_ip.v4, 4);
    return res;
  }

  static FlowKeyv4 save_reversed(const Packet& packet) noexcept
  {
    FlowKeyv4 res;
    res.FlowKey::save_reversed(packet);
    std::memcpy(res.src_ip.data(), &packet.dst_ip.v4, 4);
    std::memcpy(res.dst_ip.data(), &packet.src_ip.v4, 4);
    return res;
  }

};

struct FlowKeyv6 : FlowKey<16> {

  static FlowKeyv6 save_direct(const Packet& packet) noexcept
  {
    FlowKeyv6 res;
    res.FlowKey::save_direct(packet);
    std::memcpy(res.src_ip.data(), &packet.src_ip.v4, 16);
    std::memcpy(res.dst_ip.data(), &packet.dst_ip.v4, 16);
    return res;
  }

  static FlowKeyv16 save_reversed(const Packet& packet) noexcept
  {
    FlowKeyv16 res;
    res.FlowKey::save_reversed(packet);
    std::memcpy(res.src_ip.data(), &packet.dst_ip.v4, 16);
    std::memcpy(res.dst_ip.data(), &packet.src_ip.v4, 16);
    return res;
  }

};

} // namespace ipxp