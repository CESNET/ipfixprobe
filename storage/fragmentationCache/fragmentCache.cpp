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

#include "fragmentCache.hpp"
#include "../xxhash.h"

#include <cstring>

namespace ipxp
{

// operators for working with timeval, the operators assume that:
//   abs(time.usec) < USEC_IN_SEC && sign(time.sec) == sing(time.usec)

static inline timeval operator-(const timeval &a, const timeval &b)
{
    // number of microseconds in second
    constexpr decltype(a.tv_usec) USEC_IN_SEC = 1000000;

    auto sec = a.tv_sec - b.tv_sec;
    auto usec = a.tv_usec - b.tv_usec;

    // ensure that abs(usec) < USEC_IN_SEC
    if (usec < -USEC_IN_SEC) {
        usec += USEC_IN_SEC;
        --sec;
    } else if (usec > USEC_IN_SEC) {
        usec -= USEC_IN_SEC;
        ++sec;
    }

    // ensure that sign(sec) == sign(usec)
    if (sec > 0 && usec < 0) {
        --sec;
        usec += 1;
    } else if (sec < 0 && usec > 0) {
        ++sec;
        usec -= 1;
    }

    return timeval{ .tv_sec = sec, .tv_usec = usec };
}

static constexpr bool operator>=(const timeval &a, const timeval &b)
{
    return a.tv_sec > b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_usec >= b.tv_usec);
}

static constexpr bool operator==(const timeval &a, const timeval &b)
{
    return a.tv_sec == b.tv_sec && a.tv_usec == b.tv_usec;
}

FragmentCache::Key FragmentCache::Key::from_packet(Packet &pkt)
{
    return Key {
        pkt.ip_version,
        pkt.vlan_id,
        pkt.frag_id,
        pkt.src_ip,
        pkt.dst_ip,
    };
}

bool FragmentCache::Key::Equal::operator()(const Key &a, const Key &b) const
{
    return memcmp(&a, &b, sizeof(Key)) == 0;
}

uint64_t FragmentCache::Key::Hash::operator()(const Key &key) const
{
    return XXH64(reinterpret_cast<const void *>(&key), sizeof(Key), 0);
}

FragmentCache::Value FragmentCache::Value::from_packet(Packet &pkt)
{
    return Value {
        pkt.src_port,
        pkt.dst_port,
        pkt.ts,
    };
}

void FragmentCache::Value::fill_packet(Packet &pkt) const
{
    pkt.src_port = src_port;
    pkt.dst_port = dst_port;
}

void FragmentCache::FragTable::add(Key &&key, Value &&value)
{
    auto index = hash(key) % buckets.size();
    buckets[index].push(std::move(key), std::move(value));
}

const FragmentCache::Value *FragmentCache::FragTable::get(const Key &key) const
{
    auto index = hash(key) % buckets.size();
    auto item = buckets[index].get(key);
    return item == nullptr ? nullptr : &item->value;
}

void FragmentCache::FragTable::Bucket::push(Key &&key, Value &&value)
{
    buffer[mod_size(read + count)] = Item{ .key = std::move(key), .value = std::move(value) };

    if (is_full()) {
        read = mod_size(read + 1);
    } else {
        ++count;
    }
}

const FragmentCache::FragTable::Bucket::Item *FragmentCache::FragTable::Bucket::get(
    const Key &key) const
{
    if (is_empty()) {
        return nullptr;
    }

    // search from the last pushed
    auto count = this->count;
    while (count--) {
        auto i = mod_size(read + count);
        if (equal(buffer[i].key, key)) {
            return &buffer[i];
        }
    }

    return nullptr;
}

void FragmentCache::add_packet(Packet &pkt)
{
    auto key = Key::from_packet(pkt);
    auto info = Value::from_packet(pkt);

    fragments.add(std::move(key), std::move(info));
}

bool FragmentCache::fill_info(Packet &pkt) const
{
    auto key = Key::from_packet(pkt);
    auto val = fragments.get(key);

    if (val == nullptr || pkt.ts - val->timestamp >= timeout) {
        return false; // the table doesn't have the key, or the fragment is too old
    }

    val->fill_packet(pkt);
    return true;
}

} // namespace ipxp
