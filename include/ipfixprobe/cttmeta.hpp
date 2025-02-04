#ifndef IPXP_INPUT_CTT_HPP
#define IPXP_INPUT_CTT_HPP

#include <bits/types/struct_timeval.h>
#include <cstdint>

namespace ipxp {

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

struct Metadata_CTT {
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

}

#endif // IPXP_INPUT_CTT_HPP