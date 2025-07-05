/**
 * \file ndp.hpp
 * \brief Packet reader using NDP library for high speed capture.
 * \author Tomas Benes <benesto@fit.cvut.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2020-2021 CESNET
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
 *
 *
 *
 */
#pragma once

#include <bits/types/struct_timeval.h>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>
#include "ndpCore.hpp"

namespace ipxp {

class NdpPacketReader : public NdpPacketReaderCore
{
public:
   NdpPacketReader(const std::string& params);
   OptionsParser *get_parser() const { return new NdpOptParser(); }
   std::string get_name() const { return "ndp"; }
   InputPlugin::Result get(PacketBlock &packets);
   std::optional<CttConfig> get_ctt_config() const override;

private:
   NdpReader ndpReader;
   RxStats m_stats = {};
};

}
