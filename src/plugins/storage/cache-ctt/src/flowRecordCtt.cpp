/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief FlowRecord implementation.
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

#include "flowRecordCtt.hpp"

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <cstring>

namespace ipxp {

void FlowRecordCtt::erase()
{
   FlowRecord::erase();
   last_request_time.reset();
   can_be_offloaded = false;
   offload_mode.reset();
}

void FlowRecordCtt::create(const Packet &pkt, uint64_t hash)
{
   FlowRecord::create(pkt, hash);
   can_be_offloaded = true;
   last_request_time.reset();
}

} // ipxp