#pragma once

//#define WITH_CTT 1 // TODO REMOVE

#ifdef WITH_CTT
#include <sys/time.h>
#include <ctt_async.hpp>
#include <ctt_factory.hpp>
#include <ctt_exceptions.hpp>
#include <ctt_modes.hpp>
#include <ctt.hpp>
#include <queue>
#include <tuple>

namespace ipxp {

class CttController {
public:
    enum class OffloadMode : uint8_t {
        NO_OFFLOAD = 0x0,
        PACKET_OFFLOAD = 0x1,
        META_EXPORT = 0x2,
        PACKET_OFFLOAD_WITH_EXPORT = 0x3
    };
    enum class MetaType : uint8_t {
        FULL = 0x0,
        HALF = 0x1,
        TS_ONLY = 0x2,
        NO_META = 0x3
    };
    /**
     * @brief init the CTT.
     *
     * @param nfb_dev          The NFB device file (e.g., "/dev/nfb0").
     * @param ctt_comp_index   The index of the CTT component.
     */
    void init(const std::string& nfb_dev, unsigned ctt_comp_index);

    /**
     * @brief Command: mark a flow for offload.
     *
     * @param flow_hash_ctt    The flow hash to be offloaded.
     */
    void create_record(uint64_t flow_hash_ctt, const struct timeval& timestamp_first);

    /**
     * @brief Command: export a flow from the CTT.
     *
     * @param flow_hash_ctt    The flow hash to be exported.
     */
    void export_record(uint64_t flow_hash_ctt);

private:
    std::unique_ptr<ctt::AsyncCommander> m_commander;
    size_t key_size_bytes;
    size_t state_size_bytes;
    size_t state_mask_size_bytes;

    /**
     * @brief Assembles the state vector from the given values.
     *
     * @param offload_mode     The offload mode.
     * @param meta_type        The metadata type.
     * @param timestamp_first  The first timestamp of the flow.
     * @return A byte vector representing the assembled state vector.
     */
    std::vector<std::byte> assemble_state(
        OffloadMode offload_mode, MetaType meta_type,
        const struct timeval& timestamp_first);

    /**
     * @brief Assembles the key vector from the given flow hash.
     *
     * @param flow_hash_ctt    The flow hash.
     * @return A byte vector representing the assembled key vector.
     */
    std::vector<std::byte> assemble_key(uint64_t flow_hash_ctt);
};

} // ipxp

#endif /* WITH_CTT */
