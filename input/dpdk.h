/**
 * \file dpdk.h
 * \brief DPDK input interface for ipfixprobe.
 * \author Roman Vrana <ivrana@fit.vutbr.cz>
 * \date 2021
 */

#include <config.h>
#ifdef WITH_DPDK

#ifndef IPXP_DPDK_READER_H
#define IPXP_DPDK_READER_H

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/utils.hpp>

#include <rte_mbuf.h>
#include <memory>

namespace ipxp
{
    class DpdkOptParser : public OptionsParser
    {
    private:
        static constexpr size_t DEFAULT_MBUF_BURST_SIZE = 64;
        static constexpr size_t DEFAULT_MBUF_POOL_SIZE = 8191; // (2 ^ 13) - 1
        size_t pkt_buffer_size_;
        size_t pkt_mempool_size_;
        std::uint16_t port_num_;
    public:
        DpdkOptParser() : OptionsParser("dpdk", "Input plugin for reading packets using DPDK interface"), pkt_buffer_size_(DEFAULT_MBUF_BURST_SIZE), pkt_mempool_size_(DEFAULT_MBUF_POOL_SIZE)
        {
            register_option("b",
                            "bsize",
                            "SIZE",
                            "Size of the MBUF packet buffer. Default: " + std::to_string(DEFAULT_MBUF_BURST_SIZE),
                            [this](const char* arg){try{pkt_buffer_size_ = str2num<decltype(pkt_buffer_size_)>(arg);} catch (std::invalid_argument&){return false;} return true;},
                            RequiredArgument);
            register_option("p",
                            "port",
                            "PORT",
                            "DPDK port to be used as an input interface",
                            [this](const char* arg){try{port_num_ = str2num<decltype(port_num_)>(arg);} catch (std::invalid_argument&){return false;} return true;},
                            RequiredArgument);
            register_option("m",
                            "mem",
                            "SIZE",
                            "Size of the memory pool for received packets. Default: " + std::to_string(DEFAULT_MBUF_POOL_SIZE),
                            [this](const char* arg){try{pkt_mempool_size_ = str2num<decltype(pkt_mempool_size_)>(arg);} catch (std::invalid_argument&){return false;} return true;},
                            RequiredArgument);
        }

        size_t pkt_buffer_size() const { return pkt_buffer_size_; }

        size_t pkt_mempool_size() const { return pkt_mempool_size_; }

        std::uint16_t port_num() const { return port_num_; }
    };

    class DpdkReader : public InputPlugin
    {
    private:
        size_t port_id_;
        rte_mempool* mpool_;
        std::vector<rte_mbuf*> mbufs_;

    public:
        Result get(PacketBlock& packets) override;

        void init(const char *params) override;

        OptionsParser *get_parser() const override
        {
            return new DpdkOptParser();
        }

        std::string get_name() const override
        {
            return "dpdk";
        }
    };
}

#endif //IPXP_DPDK_READER_H
#endif