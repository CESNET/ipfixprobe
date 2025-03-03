/**
 * \file
 * \brief Implementation of DpdkTelemetry class and helper functions for rings and mempools
 * information retrieval.
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

#include "dpdkTelemetry.hpp"

#include <stdexcept>
#include <string>

#include <rte_eal_memconfig.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_tailq.h>

namespace ipxp {

static void createRingsInfo(struct rte_ring* ring, void* arg)
{
    std::string& buffer = *reinterpret_cast<std::string*>(arg);
    unsigned int count;
    unsigned int freeCount;
    unsigned int size;
    unsigned int capacity;
    int isFull;
    int isEmpty;

    count = rte_ring_count(ring);
    freeCount = rte_ring_free_count(ring);
    size = rte_ring_get_size(ring);
    capacity = rte_ring_get_capacity(ring);
    isFull = rte_ring_full(ring);
    isEmpty = rte_ring_empty(ring);

    if (buffer.empty()) {
        buffer += "name ";
        buffer += "flags ";
        buffer += "usedCount ";
        buffer += "freeCount ";
        buffer += "size ";
        buffer += "capacity ";
        buffer += "status";
        buffer += "\n";
    }

    buffer += std::string(ring->name) + " ";
    buffer += std::to_string(ring->flags) + " ";
    buffer += std::to_string(count) + " ";
    buffer += std::to_string(freeCount) + " ";
    buffer += std::to_string(size) + " ";
    buffer += std::to_string(capacity) + " ";
    buffer += isFull == 1 ? "full" : isEmpty == 1 ? "empty" : "inUse";
    buffer += "\n";
}

static void ringsWalk(void (*fnc)(struct rte_ring*, void* ctx), void* arg)
{
    TAILQ_HEAD(rte_ring_list, rte_tailq_entry);
    struct rte_ring_list* rings;
    struct rte_tailq_entry* entry;

    rte_mcfg_tailq_read_lock();

    rings = RTE_TAILQ_LOOKUP(RTE_TAILQ_RING_NAME, rte_ring_list);
    if (rings == nullptr) {
        rte_mcfg_tailq_read_unlock();
        throw std::runtime_error("RTE_TAILQ_LOOKUP(" RTE_TAILQ_RING_NAME ") failed");
    }

    try {
        TAILQ_FOREACH(entry, rings, next)
        {
            fnc((struct rte_ring*) entry->data, arg);
        }
    } catch (...) {
        rte_mcfg_tailq_read_unlock();
        throw;
    }

    rte_mcfg_tailq_read_unlock();
}

static void createMempoolsInfo(struct rte_mempool* mempool, std::string& buffer)
{
    const rte_mempool_ops* ops = rte_mempool_get_ops(mempool->ops_index);
    const unsigned int avail = rte_mempool_avail_count(mempool);
    const unsigned int inUse = rte_mempool_in_use_count(mempool);
    const int isFull = rte_mempool_full(mempool);
    const int isEmpty = rte_mempool_empty(mempool);
    const uint64_t totalSize = static_cast<uint64_t>(mempool->populated_size)
        * static_cast<uint64_t>((mempool->elt_size + mempool->header_size + mempool->trailer_size));

    if (buffer.empty()) {
        buffer += "name ";
        buffer += "socketID ";
        buffer += "flags ";
        buffer += "poolID ";
        buffer += "size ";
        buffer += "cacheSize ";
        buffer += "elementSize ";
        buffer += "headerSize ";
        buffer += "trailerSize ";
        buffer += "totalSize ";
        buffer += "availableCount ";
        buffer += "usedCount ";
        buffer += "status ";
        buffer += "Ops";
        buffer += "\n";
    }

    buffer += std::string(mempool->name) + " ";
    buffer += std::to_string(mempool->socket_id) + " ";
    buffer += std::to_string(mempool->flags) + " ";
    buffer += std::to_string(mempool->pool_id) + " ";
    buffer += std::to_string(mempool->size) + " ";
    buffer += std::to_string(mempool->cache_size) + " ";
    buffer += std::to_string(mempool->elt_size) + " ";
    buffer += std::to_string(mempool->header_size) + " ";
    buffer += std::to_string(mempool->trailer_size) + " ";
    buffer += std::to_string(totalSize) + " ";
    buffer += std::to_string(avail) + " ";
    buffer += std::to_string(inUse) + " ";
    buffer += (isFull == 1 ? "full " : isEmpty == 1 ? "empty " : "inUse ");
    buffer += (ops != nullptr ? std::string(ops->name) : "(none)");
    buffer += "\n";
}

static std::string getMempoolsInfo()
{
    struct Walker {
        std::string buffer;
        std::exception_ptr exc = nullptr;
        void operator()(rte_mempool* pool)
        {
            if (exc != nullptr) {
                return;
            }
            try {
                createMempoolsInfo(pool, buffer);
            } catch (...) {
                exc = std::current_exception();
            }
        }
    };
    Walker walker;

    rte_mempool_walk(
        [](rte_mempool* pool, void* arg) { (*reinterpret_cast<Walker*>(arg))(pool); },
        &walker);
    if (walker.exc != nullptr) {
        std::rethrow_exception(walker.exc);
    }
    return walker.buffer;
}

static std::string getRingsInfo()
{
    std::string buffer;
    ringsWalk(&createRingsInfo, &buffer);
    return buffer;
}

struct AppFsFile {
    std::string name;
    telemetry::FileOps ops;
};

static std::vector<AppFsFile> getAppFsFiles()
{
    std::vector<AppFsFile> files = {
        {
            .name = "mempools",
            .ops = {
                .read = []() { return getMempoolsInfo(); },
            },
        },
        {
            .name = "rings",
            .ops = {
                .read = []() { return getRingsInfo(); },
            },
        },
    };
    return files;
}

DpdkTelemetry::DpdkTelemetry(const std::shared_ptr<telemetry::Directory>& dpdkDir)
{
    for (auto [name, ops] : getAppFsFiles()) {
        if (dpdkDir->getEntry(name)) {
            continue;
        }
        auto file = dpdkDir->addFile(name, ops);
        m_holder.add(file);
    }
}

} // namespace ct
