/**
 * @file
 * @brief Pcap reader based on libpcap
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <pcap/pcap.h>
#include <ipfixprobe.hpp>

#include <string>
#include <cstdint>

namespace ipxp {

/*
 * @brief Minimum snapshot length of pcap handle.
 */
#define MIN_SNAPLEN 120

/*
 * @brief Maximum snapshot length of pcap handle.
 */
#define MAX_SNAPLEN 65535

// Read timeout in miliseconds for pcap_open_live function.
#define READ_TIMEOUT 1000

/**
 * @brief Class for reading packets from file or network interface.
 */
class PcapReader : public InputPlugin {
public:
    PcapReader(const std::string& params);
    ~PcapReader();

    void init(const char* params);
    void close();
    OptionsParser* get_parser() const;
    std::string get_name() const { return "pcap"; }
    InputPlugin::Result get(PacketBlock& packets);

private:
    pcap_t* m_handle; /**< libpcap file handle */
    uint16_t m_snaplen;
    int m_datalink;
    bool m_live; /**< Capturing from network interface */
    bpf_u_int32 m_netmask; /**< Network mask. Used when setting filter */

    void open_file(const std::string& file);
    void open_ifc(const std::string& ifc);
    void set_filter(const std::string& filter_str);

    void check_datalink();
    void print_available_ifcs();
};

} // namespace ipxp
