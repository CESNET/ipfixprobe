/**
 * \file flowkeyv4.hpp
 * \brief FlowKey class specialization for ipv4
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

#ifndef IPFIXPROBE_CACHE_FLOW_KEY_V4_H
#define IPFIXPROBE_CACHE_FLOW_KEY_V4_H

#include "flowkey.hpp"

namespace ipxp {

struct __attribute__((packed)) FlowKeyV4 : public FlowKey<4> {
    FlowKeyV4& operator=(const Packet& pkt) noexcept;
    FlowKeyV4& save_reversed(const Packet& pkt) noexcept;
    FlowKeyV4& save_sorted(const Packet& pkt) noexcept;
};

} // namespace ipxp

#endif // IPFIXPROBE_CACHE_FLOW_KEY_V4_H
