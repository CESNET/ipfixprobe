/**
 * \file ndp-ctt.hpp
 * \brief Packet reader using NDP library for high speed capture, with
            Connection Tracking Table (ctt).
 * \author Jaroslav Pesek <jaroslav.pesek@fit.cvut.cz>
 * \date 2024
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

#ifndef IPXP_INPUT_NDP_CTT_HPP
#define IPXP_INPUT_NDP_CTT_HPP

#include <cstdint>
#include <nfb/nfb.h>
#include <nfb/ndp.h>
#include <ctt.hpp>
#include <ctt_factory.hpp>
#include <ctt_modes.hpp>
#include <ctt_exceptions.hpp>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

class NdpCttOptParser : public OptionsParser
{
public:
    std::string m_dev;
    uint64_t m_id;

    NdpCttOptParser() : OptionsParser("ndp-ctt", "Input plugin for reading packets from a ndp device with Connection Tracking Table"), m_dev(""), m_id(0)
    {
        register_option("d", "dev", "PATH", "Path to a device file", [this](const char *arg){m_dev = arg; return true;}, OptionFlags::RequiredArgument);
        register_option("I", "id", "NUM", "Link identifier number",
            [this](const char *arg){try {m_id = str2num<decltype(m_id)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
            OptionFlags::RequiredArgument);
    }
};

class NdpCttPacketReader : public InputPlugin
{
public:
    NdpCttPacketReader();
    ~NdpCttPacketReader();

    void init(const char *params) override;
    void close() override;
    OptionsParser *get_parser() const override { return new NdpCttOptParser(); }
    std::string get_name() const override { return "ndp-ctt"; }
    InputPlugin::Result get(PacketBlock &packets) override;

    void configure_telemetry_dirs(
      std::shared_ptr<telemetry::Directory> plugin_dir, 
      std::shared_ptr<telemetry::Directory> queues_dir) override;

private:
    struct RxStats {
        uint64_t receivedPackets;
        uint64_t receivedBytes;
    };

    telemetry::Content get_queue_telemetry();

    RxStats m_stats = {};

    void init_ifc(const std::string &dev);

    std::unique_ptr<nfb_device, decltype(&nfb_close)> _nfbDevice {nullptr, &nfb_close};

};

} // namespace ipxp

#endif // IPXP_INPUT_NDP_CTT_HPP

