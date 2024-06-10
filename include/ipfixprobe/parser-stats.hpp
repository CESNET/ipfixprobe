/**
 * \file
 * \brief Definition of the ParserStats structure for storing parser statistics
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2024
 */
/*
 * Copyright (C) 2024 CESNET
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

namespace ipxp {

/**
 * \brief Structure for storing parser statistics.
 */
struct ParserStats {
   uint64_t mpls_packets;
   uint64_t vlan_packets;
   uint64_t pppoe_packets;
   uint64_t trill_packets;

   uint64_t ipv4_packets;
   uint64_t ipv6_packets;

   uint64_t tcp_packets;
   uint64_t udp_packets;

   uint64_t seen_packets;
   uint64_t unknown_packets;
};

} // namespace ipxp
