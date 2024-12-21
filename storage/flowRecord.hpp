#pragma once

#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <cstdint>

namespace ipxp {

class alignas(64) FlowRecord
{
    uint64_t m_hash;

    public:
    Flow m_flow;
#ifdef WITH_CTT
    Flow m_delayed_flow;
    bool m_delayed_flow_waiting;
#endif /* WITH_CTT */

    FlowRecord();
    ~FlowRecord();

    void erase();
    void reuse();

    bool is_empty() const noexcept;
    bool belongs(uint64_t pkt_hash) const noexcept;
    void create(const Packet &pkt, uint64_t pkt_hash);
    void update(const Packet &pkt, bool src);
};

} // ipxp
