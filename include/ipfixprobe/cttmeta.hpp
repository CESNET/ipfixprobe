#pragma once

#include <cstdint>
#include <optional>
#include <config.h>
#include <bits/types/struct_timeval.h>

#ifdef WITH_CTT

namespace ipxp {

static uint64_t extract(const uint8_t* bitvec, size_t start_bit, size_t bit_length) {
    size_t start_byte = start_bit / 8;
    size_t end_bit = start_bit + bit_length;
    size_t end_byte = (end_bit + 7) / 8;
    uint64_t value = 0;
    for (size_t i = 0; i < end_byte - start_byte; ++i) {
        value |= static_cast<uint64_t>(bitvec[start_byte + i]) << (8 * i);
    }
    value >>= (start_bit % 8);
    uint64_t mask = (bit_length == 64) ? ~0ULL : ((1ULL << bit_length) - 1);
    return value & mask;
}

enum MessageType : uint8_t
{
    FRAME_AND_FULL_METADATA = 0x0, ///< Frame and full metadata
    FRAME_AND_HALF_METADATA = 0x1, ///< Frame and half metadata
    FRAME_WITH_TIMESTAMP    = 0x2, ///< Frame with timestamp
    FRAME_WITH_NO_METADATA  = 0x3, ///< Frame with no metadata
    ONLY_FULL_METADATA      = 0x4, ///< Only full metadata
    FLOW_EXPORT             = 0xF  ///< Flow export
};

enum CsumStatus : uint8_t {
    CSUM_UNKNOWN = 0x0, ///< No information about the checksum
    CSUM_BAD     = 0x1, ///< The checksum in the packet is wrong
    CSUM_GOOD    = 0x2, ///< The checksum in the packet is valid
    CSUM_NONE    = 0x3  ///< Checksum not correct but header integrity verified
};

enum ParserStatus : uint8_t {
    PA_OK      = 0x0, ///< Parsing completed successfully
    PA_UNKNOWN = 0x1, ///< Parser stopped at an unknown protocol
    PA_LIMIT   = 0x2, ///< Parser stopped at its own limit (e.g., VLAN=4)
    PA_ERROR   = 0x3  ///< Error in protocol header or parsing overflow
};

enum L2PType : uint8_t {
    L2_UNKNOWN          = 0x0, ///< Unknown L2 protocol
    L2_ETHER_IP         = 0x1, ///< Ethernet with IP payload
    L2_ETHER_TIMESYNC   = 0x2, ///< Ethernet with TimeSync protocol
    L2_ETHER_ARP        = 0x3, ///< Ethernet with ARP protocol
    L2_ETHER_LLDP       = 0x4, ///< Ethernet with LLDP protocol
    L2_ETHER_NSH        = 0x5, ///< Ethernet with NSH protocol
    L2_ETHER_VLAN       = 0x6, ///< Ethernet with VLAN tagging
    L2_ETHER_QINQ       = 0x7, ///< Ethernet with QinQ tagging
    L2_ETHER_PPPOE      = 0x8, ///< Ethernet with PPPoE encapsulation
    L2_ETHER_FCOE       = 0x9, ///< Ethernet with FCoE protocol
    L2_ETHER_MPLS       = 0xA  ///< Ethernet with MPLS
};

enum L3PType : uint8_t {
    L3_UNKNOWN   = 0x0, ///< Unknown L3 protocol
    L3_IPV4      = 0x1, ///< IPv4 protocol
    L3_IPV4_EXT  = 0x3, ///< IPv4 with extensions
    L3_IPV6      = 0x4, ///< IPv6 protocol
    L3_IPV6_EXT  = 0xC  ///< IPv6 with extensions
};

enum L4PType : uint8_t {
    L4_UNKNOWN = 0x0, ///< Unknown L4 protocol
    L4_TCP     = 0x1, ///< TCP protocol
    L4_UDP     = 0x2, ///< UDP protocol
    L4_FRAG    = 0x3, ///< Fragmented packet
    L4_SCTP    = 0x4, ///< SCTP protocol
    L4_ICMP    = 0x5, ///< ICMP protocol
    L4_NONFRAG = 0x6, ///< Non-fragmented packet
    L4_IGMP    = 0x7  ///< IGMP protocol
};

struct CttMetadata {
    constexpr static size_t SIZE = 32;

    static std::optional<CttMetadata> parse(const uint8_t* data, size_t length) noexcept
    {
        CttMetadata metadata;
        if (length != CttMetadata::SIZE) {
            return std::nullopt;
        }

        metadata.ts.tv_usec      = extract(data, 0,   32);
        metadata.ts.tv_sec       = extract(data, 32,  32);
        metadata.vlan_tci        = extract(data, 64,  16);
        metadata.vlan_vld        = extract(data, 80,  1);
        metadata.vlan_stripped   = extract(data, 81,  1);
        metadata.ip_csum_status  = static_cast<CsumStatus>(extract(data, 82,  2));
        metadata.l4_csum_status  = static_cast<CsumStatus>(extract(data, 84,  2));
        metadata.parser_status   = static_cast<ParserStatus>(extract(data, 86,  2));
        metadata.ifc             = extract(data, 88,  8);
        metadata.filter_bitmap   = extract(data, 96,  16);
        metadata.ctt_export_trig = extract(data, 112, 1);
        metadata.ctt_rec_matched = extract(data, 113, 1);
        metadata.ctt_rec_created = extract(data, 114, 1);
        metadata.ctt_rec_deleted = extract(data, 115, 1);
        metadata.flow_hash       = extract(data, 128, 64);
        metadata.l2_len          = extract(data, 192, 7);
        metadata.l3_len          = extract(data, 199, 9);
        metadata.l4_len          = extract(data, 208, 8);
        metadata.l2_ptype        = static_cast<L2PType>(extract(data, 216, 4));
        metadata.l3_ptype        = static_cast<L3PType>(extract(data, 220, 4));
        metadata.l4_ptype        = static_cast<L4PType>(extract(data, 224, 4));

        return metadata;
    }
    struct timeval ts;             ///< Timestamp; invalid if all bits are 1
    uint16_t vlan_tci;             ///< VLAN Tag Control Information from outer VLAN
    bool vlan_vld : 1;             ///< VLAN valid flag; indicates if VLAN TCI is valid
    bool vlan_stripped : 1;        ///< VLAN stripped flag; outer VLAN only
    CsumStatus ip_csum_status : 2; ///< IP checksum status
    CsumStatus l4_csum_status : 2; ///< Layer 4 checksum status
    ParserStatus parser_status : 2;///< Final state of FPGA parser
    uint8_t ifc;                   ///< Interface (IFC) number
    uint16_t filter_bitmap;        ///< Filter bitmap; each filter rule can have several mark bits
    bool ctt_export_trig : 1;      ///< CTT flag; packet triggered export in CTT
    bool ctt_rec_matched : 1;      ///< CTT flag; packet matched record in CTT
    bool ctt_rec_created : 1;      ///< CTT flag; packet created record in CTT
    bool ctt_rec_deleted : 1;      ///< CTT flag; packet deleted record in CTT
    uint64_t flow_hash;            ///< Flow hash; not the same as RSS hash
    uint8_t l2_len : 7;            ///< Length of the L2 layer, if known
    uint16_t l3_len : 9;           ///< Length of the L3 layer, if known
    uint8_t l4_len : 8;            ///< Length of the L4 layer, if known
    L2PType l2_ptype : 4;          ///< Type of the L2 layer
    L3PType l3_ptype : 4;          ///< Type of the L3 layer
    L4PType l4_ptype : 4;          ///< Type of the L4 layer
};

enum CttExportReason : uint8_t {
    MANAGEMENT_UNIT = 0, ///< Exported by CTT MU
    SOFTWARE = 1, ///< Exported by software
    CTT_FULL = 2, ///< CTT is full, state was replaced
    RESERVED = 3 ///< Reserved
};

/**
 * \brief CTT export metadata
 * Valid only if CttExportReason is MANAGEMENT_UNIT
 */
enum ManagementUnitExportReason : uint8_t {
    COUNTER_OVERFLOW = 0b1, ///< Counter overflow
    TCP_EOF = 0b10, ///< TCP connection ended
    ACTIVE_TIMEOUT = 0b100, ///< Active timeout
};

enum IpVersion : uint8_t {
    IPv4 = 0, ///< IPv4
    IPv6 = 1  ///< IPv6
};

enum OffloadMode : uint8_t {
    FULL_PACKET_WITH_METADATA_AND_EXPORT = 0,    ///< Packet with metadata and export
    TRIMMED_PACKET_WITH_METADATA_AND_EXPORT = 1, ///< Trimmed packet with metadata and export
    ONLY_FULL_METADATA_AND_EXPORT = 2,           ///< Only full metadata and export
    ONLY_EXPORT = 3                              ///< Only export
};

enum MetadataType : uint8_t {
    FULL_METADATA = 0,  ///< Full metadata
    HALF_METADATA = 1,  ///< Half metadata
    TIMESTAMP_ONLY = 2, ///< Timestamp only
    NO_METADATA = 3     ///< No metadata
};

struct timeval32 {
    uint32_t tv_usec;
    uint32_t tv_sec;
};

struct CttState {
    constexpr static size_t SIZE = 71;
    uint8_t dma_channel;  ///< DMA channel
    timeval32 time_first; ///< Time of the first packet in the flow
    timeval32 time_last; ///< Time of the last packet in the flow
    uint64_t src_ip[2]; ///< Source IP address
    uint64_t dst_ip[2]; ///< Destination IP address
    uint8_t ip_version : 1; ///< IP version
    uint8_t ip_proto : 8; ///< IP protocol from the first packet
    uint16_t src_port : 16; ///< Source port from the first packet
    uint16_t dst_port : 16; ///< Destination port from the first packet
    uint8_t tcp_flags : 6; ///< TCP flags cumulative from source to destination
    uint8_t tcp_flags_rev : 6; ///< TCP flags cumulative from destination to source
    uint16_t packets : 16; ///< Number of packets in the flow source to destination
    uint16_t packets_rev : 16; ///< Number of packets in the flow destination to source
    uint32_t bytes : 32;  ///< Number of bytes in the flow source to destination
    uint32_t bytes_rev : 32; ///< Number of bytes in the flow destination to source
    uint16_t limit_size : 16; /** All packets are trimmed to this size if limit_size > 0 or to l4 header if 0
                                                    when offload_mode == TRIMMED_PACKET_WITH_METADATA_AND_EXPORT set*/
    OffloadMode offload_mode : 2; ///< Offload mode
    MetadataType meta_type : 2; ///< Metadata type
    bool was_exported : 1; ///< Was exported
    uint8_t byte_fill : 6;
}__attribute((packed));

static_assert(sizeof(CttState) == CttState::SIZE, "CttState size mismatch");

struct CttExport {
    constexpr static size_t SIZE = 80;

    static std::optional<CttExport> parse(const uint8_t* data, size_t length) noexcept
    {
        CttExport export_data;
        if (length != CttExport::SIZE) {
          return std::nullopt;
        }

        export_data.original_record = extract(data, 0, 1);
        export_data.updated_record = extract(data, 1, 1);
        export_data.exported_after_modify = extract(data, 2, 1);
        export_data.reason = static_cast<CttExportReason>(extract(data, 3, 2));
        export_data.mu_reason = static_cast<ManagementUnitExportReason>(extract(data, 5, 3));
        export_data.flow_hash_ctt = extract(data, 8, 64);
        export_data.state.dma_channel = extract(data, 72, 8);
        export_data.state.time_first.tv_usec = extract(data, 80, 32);
        export_data.state.time_first.tv_sec = extract(data, 112, 32);
        export_data.state.time_last.tv_usec = extract(data, 144, 32);
        export_data.state.time_last.tv_sec = extract(data, 176, 32);
        *reinterpret_cast<uint64_t*>(&export_data.state.src_ip) = extract(data, 208, 64);
        *(reinterpret_cast<uint64_t*>(&export_data.state.src_ip) + 1) = extract(data, 272, 64);
        *reinterpret_cast<uint64_t*>(&export_data.state.dst_ip) = extract(data, 336, 64);
        *(reinterpret_cast<uint64_t*>(&export_data.state.dst_ip) + 1) = extract(data, 400, 64);
        export_data.state.ip_version = static_cast<IpVersion>(extract(data, 464, 1));
        export_data.state.ip_proto = extract(data, 465, 8);
        export_data.state.src_port = extract(data, 473, 16);
        export_data.state.dst_port = extract(data, 489, 16);
        export_data.state.tcp_flags = extract(data, 505, 6);
        export_data.state.tcp_flags_rev = extract(data, 511, 6);
        export_data.state.packets = extract(data, 517, 16);
        export_data.state.packets_rev = extract(data, 533, 16);
        export_data.state.bytes = extract(data, 549, 32);
        export_data.state.bytes_rev = extract(data, 581, 32);
        export_data.state.limit_size = extract(data, 613, 16);
        export_data.state.offload_mode = static_cast<OffloadMode>(extract(data, 629, 2));
        export_data.state.meta_type = static_cast<MetadataType>(extract(data, 631, 2));
        export_data.state.was_exported = extract(data, 633, 1);

        return std::make_optional(export_data);
    }

    bool original_record : 1; ///< PV flag
    bool updated_record : 1;  ///< WB flag
    bool exported_after_modify : 1; ///< Exported after modification if 1 or before if 0
    CttExportReason reason : 2; ///< Reason for export
    ManagementUnitExportReason mu_reason : 3; ///< Management unit export reason
    uint64_t flow_hash_ctt; ///< Flow hash in CTT
    CttState state; ///< State of the flow
} __attribute((packed));

static_assert(sizeof(CttExport) == CttExport::SIZE, "CttExport size mismatch");

#if defined(__GNUC__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 4))
#error "This code requires GCC version 4.4 or higher to ensure consistent bit-field ordering."
#endif

}

#endif // WITH_CTT
