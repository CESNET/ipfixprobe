/**
 * \file fragmentCache.hpp
 * \brief Cache for fragmented packets
 * \author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * \date 2023
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
 *     notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef IPXP_STORAGE_FRAGMENTATION_CACHE_FRAGMENT_CACHE
#define IPXP_STORAGE_FRAGMENTATION_CACHE_FRAGMENT_CACHE

// the log2 of the size of buckets (e.g. 2 is size of 4)
#ifndef LOG2_FRAG_CACHE_BUCKET_SIZE
#define LOG2_FRAG_CACHE_BUCKET_SIZE 2
#endif // LOG2_FRAG_CACHE_BUCKET_SIZE

// default timeout for fragmented packets, 3 seconds
#define FRAG_CACHE_DEFAULT_TIMEOUT (timeval { .tv_sec = 3, .tv_usec = 0 })
// default number of buckets in fragmentation cache, prime for better performance
#define FRAG_CACHE_DEFAULT_BUCKET_COUNT 10007

#include <cstdint>
#include <vector>
#include <array>

#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipaddr.hpp>

namespace ipxp {

class FragmentCache {
public:
    /**
     * @brief Construct a new Fragmentation Cache
     *
     * @param bucket_count number of buckets in the cache, use prime for better performance
     * @param timeout cached packets older than this are considered invalid
     */
    FragmentCache(size_t bucket_count, timeval timeout)
        : fragments(bucket_count), timeout(timeout) {}

    /**
     * @brief Construct a new Fragmentation Cache with default bucket count and timeout
     *
     */
    FragmentCache() : FragmentCache(FRAG_CACHE_DEFAULT_BUCKET_COUNT, FRAG_CACHE_DEFAULT_TIMEOUT) {}

    /**
     * @brief If the packet is fragmented, add it to cache or fill the missing info from chace
     *
     * @return true if the packet is fragmented
     */
    inline bool cache_packet(Packet &pkt) {
        // packet is fragmented if 'frag_off != 0 || more_fragments'
        // only the first fragment has always 'frag_off == 0 && more_fragments'
        if (pkt.frag_off == 0) {
            if (!pkt.more_fragments) {
                ++not_fragmented_count;
                return false; // packet is not fragmented
            }

            // first part of the fragmented packet
            ++fragmented_count;
            ++fragment_count;
            add_packet(pkt);
            return true;
        }

        // middle/last fragment

        // if fill_info returns false, this packet fragment came before
        // the first fragment
        ++fragment_count;
        if (!fill_info(pkt)) {
            ++unmached_fragment_count;
        }
        return true;
    }

    /**
     * @brief gets total number of packets that were not fragmented
     *
     * stats:
     * total packets == not_fragmented_count + fragment_count
     * avg fragments per fragmented packet = fragment_count / fragmented_count
     *
     * @return total number of packets that were not fragmented
     */
    inline size_t get_not_fragmented_count() const { return not_fragmented_count; }

    /**
     * @brief gets total number of packets that were fragmented
     *
     * stats:
     * total packets == not_fragmented_count + fragment_count
     * avg fragments per fragmented packet = fragment_count / fragmented_count
     *
     * @return total number of packets that were fragmented
     */
    inline size_t get_fragmented_count() const { return fragmented_count; }

    /**
     * @brief gets total number of fragments in all fragmented packets
     *
     * stats:
     * total packets == not_fragmented_count + fragment_count
     * avg fragments per fragmented packet = fragment_count / fragmented_count
     *
     * @return total number of fragments in all fragmented packets
     */
    inline size_t get_fragment_count() const { return fragment_count; }

    /**
     * @brief gets total number of fragments that weren't reassembled
     *
     * stats:
     * total packets == not_fragmented_count + fragment_count
     * avg fragments per fragmented packet = fragment_count / fragmented_count
     *
     * @return total number of fragments that weren't reassembled
     */
    inline size_t get_unmached_fragment_count() const { return fragment_count; }

private:
    // private types
    struct __attribute__((packed)) Key {
        // IP::v4 / IP::v6, 16-bit value only to align the struct size to 40
        uint16_t ipv;

        uint16_t vlan_id;
        uint32_t frag_id;

        // when ipv = 4, only first 4 bytes are set, the rest is 0
        ipaddr_t src_ip;
        ipaddr_t dst_ip;

        static Key from_packet(Packet &pkt);

        struct Equal
        {
            bool operator()(const Key &a, const Key &b) const;
        }; // Equal

        struct Hash
        {
            uint64_t operator()(const Key &key) const;
        };// Hash
    }; // Key

    struct Value {
        uint16_t src_port;
        uint16_t dst_port;
        timeval timestamp;

        static Value from_packet(Packet &pkt);
        void fill_packet(Packet &pkt) const;
    }; // Value

    class FragTable {
    public:
        FragTable(size_t bucket_count) : buckets(bucket_count) {}

        void add(Key &&key, Value &&value);
        const Value *get(const Key &key) const;
    private:
        // const size circullar buffer with fifo interface
        class Bucket {
        public:
            struct Item {
                Key key;
                Value value;
            }; // Item

            Bucket() : read(0), count(0), buffer() {}

            // number of items in the fifo
            inline size_t get_count() const { return count; }
            // number of items this fifo is capable of holding at once
            constexpr size_t size() const { return buffer.size(); }
            inline bool is_empty() const { return count == 0; }
            inline bool is_full() const { return count == size(); }

            // this may override old data
            void push(Key &&key, Value &&value);
            // returns null if the key is not present
            const Item *get(const Key &key) const;
        private:
            // index of the first item in the buffer
            size_t read;
            size_t count;

            Key::Equal equal;

            // buffer.size is always power of 2
            std::array<Item, 1 << LOG2_FRAG_CACHE_BUCKET_SIZE> buffer;

            // returns value % buffer.size
            // for negative numbers returns the positive result (e.g. -1 % 4 == 3)
            constexpr size_t mod_size(size_t value) const { return value & (size() - 1); }
        }; // Bucket

        Key::Hash hash;
        std::vector<Bucket> buckets;
    }; // FragMap

    // end of private types, continues FragmentCache

    // adds new packet to the cache
    void add_packet(Packet &pkt);
    // fills the missing info in pkt, returns false if the info is not in
    // the cache
    bool fill_info(Packet &pkt) const;

    FragTable fragments;
    timeval timeout;

    // stats
    size_t not_fragmented_count;
    size_t fragmented_count;
    size_t fragment_count;
    size_t unmached_fragment_count;
}; // FragmentCache

} // namespace ipxp

#endif // ifdef IPXP_STORAGE_FRAGMENTATION_CACHE_FRAGMENT_CACHE
