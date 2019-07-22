/**
 * \file types.h
 * \date 2019
 * \author Jiri Havranek <havranek@cesnet.cz>
 */
/*
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

 * This software is provided ``as is'', and any express or implied
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
*/

#ifndef P4E_GENERATED_TYPES
#define P4E_GENERATED_TYPES

#include <stdint.h>
#include <sys/time.h>


struct ethernet_h { 
    uint64_t dst_addr;
    uint64_t src_addr;
    uint16_t ethertype;
};
struct ieee802_1q_h { 
    uint8_t pcp;
    uint8_t cfi;
    uint16_t vid;
    uint16_t ethertype;
};
struct ieee802_1ah_h { 
    uint8_t prio;
    uint8_t drop;
    uint8_t nca;
    uint8_t res1;
    uint8_t res2;
    uint32_t isid;
};
struct etherip_h { 
    uint8_t version;
    uint16_t reserved;
};
struct mpls_h { 
    uint32_t label;
    uint8_t tc;
    uint8_t bos;
    uint8_t ttl;
};
struct eompls_h { 
    uint8_t zero;
    uint16_t res;
    uint16_t seq_num;
};
struct trill_h { 
    uint8_t version;
    uint8_t res;
    uint8_t m;
    uint8_t op_len;
    uint8_t hop_cnt;
    uint16_t egress_nick;
    uint16_t ingress_nick;
};
struct pppoe_h { 
    uint8_t version;
    uint8_t type;
    uint8_t code;
    uint16_t sid;
    uint16_t len;
};
struct pptp_comp_h { 
    uint16_t proto;
};
struct pptp_uncomp_h { 
    uint8_t address;
    uint8_t cntrl;
    uint16_t proto;
};
struct pptp_uncomp_proto_h { 
    uint16_t proto;
};
struct pptp_comp_proto_h { 
    uint8_t proto;
};
struct ipv4_h { 
    uint8_t version;
    uint8_t ihl;
    uint8_t diffserv;
    uint16_t total_len;
    uint16_t identification;
    uint8_t flags;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};
struct ipv6_h { 
    uint8_t version;
    uint8_t traffic_class;
    uint32_t flow_label;
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
};
struct ipv6_hop_opt_h { 
    uint8_t next_hdr;
    uint8_t hdr_len;
};
struct ipv6_dst_opt_h { 
    uint8_t next_hdr;
    uint8_t hdr_len;
};
struct ipv6_routing_h { 
    uint8_t next_hdr;
    uint8_t hdr_len;
};
struct ipv6_fragment_h { 
    uint8_t next_hdr;
    uint8_t res1;
    uint16_t frag_offset;
    uint8_t res2;
    uint8_t m;
    uint32_t id;
};
struct ipv6_ah_h { 
    uint8_t next_hdr;
    uint8_t len;
    uint16_t res;
    uint32_t spi;
};
struct gre_h { 
    uint8_t C;
    uint8_t R;
    uint8_t K;
    uint8_t S;
    uint8_t s;
    uint8_t recur;
    uint8_t A;
    uint8_t flags;
    uint8_t ver;
    uint16_t proto;
};
struct gre_sre_h { 
    uint16_t addr_family;
    uint8_t offset;
    uint8_t length;
};
struct l2f_h { 
    uint8_t F;
    uint8_t K;
    uint8_t P;
    uint8_t S;
    uint8_t res;
    uint8_t C;
    uint8_t version;
};
struct l2tp_h { 
    uint8_t type;
    uint8_t length;
    uint8_t res1;
    uint8_t seq;
    uint8_t res2;
    uint8_t offset;
    uint8_t priority;
    uint8_t res3;
    uint8_t version;
};
struct vxlan_h { 
    uint8_t gbp_ext;
    uint8_t res1;
    uint8_t vni_flag;
    uint8_t res2;
    uint8_t dont_learn;
    uint8_t res3;
    uint8_t policy_applied;
    uint8_t res4;
    uint16_t gpolicy_id;
    uint32_t vni;
    uint8_t res5;
};
struct sctp_h { 
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t verif_tag;
    uint32_t checksum;
};
struct icmp_h { 
    uint8_t type_;
    uint8_t code;
    uint16_t hdr_checksum;
    uint32_t rest;
};
struct icmpv6_h { 
    uint8_t type_;
    uint8_t code;
    uint16_t hdr_checksum;
    uint32_t rest;
};
struct tcp_h { 
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t res;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};
struct udp_h { 
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
struct igmp_v2_h { 
    uint8_t type;
    uint8_t max_resp_time;
    uint16_t checksum;
    uint32_t group_addr;
};
struct igmp_v3_h { 
    uint8_t res;
    uint8_t S;
    uint8_t QRV;
    uint8_t QQIC;
    uint16_t N;
};
struct gtp_v0_h { 
    uint8_t version;
    uint8_t proto_type;
    uint8_t res1;
    uint8_t snn;
    uint8_t type;
    uint16_t length;
    uint16_t seq_num;
    uint16_t flow_label;
    uint8_t sndcp_num;
    uint32_t res2;
    uint64_t tid;
};
struct gtp_v1_h { 
    uint8_t version;
    uint8_t proto_type;
    uint8_t res;
    uint8_t E;
    uint8_t S;
    uint8_t PN;
    uint8_t type;
    uint16_t length;
    uint32_t TEID;
};
struct gtp_v1_next_hdr_h { 
    uint8_t next_hdr;
};
struct gtp_v2_h { 
    uint8_t version;
    uint8_t piggy_flag;
    uint8_t TEID_flag;
    uint8_t spare;
    uint8_t type;
    uint16_t length;
};
struct teredo_auth_h { 
    uint8_t zero;
    uint8_t type;
    uint8_t id_len;
    uint8_t auth_len;
};
struct teredo_origin_h { 
    uint8_t zero;
    uint8_t type;
    uint16_t port;
    uint32_t ip;
};
struct genv_h { 
    uint8_t version;
    uint8_t opt_len;
    uint8_t oam;
    uint8_t critical;
    uint8_t res1;
    uint16_t proto;
    uint32_t vni;
    uint8_t res2;
};
struct genv_opt_a_h { 
    uint16_t opt_class;
    uint8_t opt_type;
    uint8_t res;
    uint8_t opt_len;
    uint32_t data;
};
struct genv_opt_b_h { 
    uint16_t opt_class;
    uint8_t opt_type;
    uint8_t res;
    uint8_t opt_len;
    uint64_t data;
};
struct genv_opt_c_h { 
    uint16_t opt_class;
    uint8_t opt_type;
    uint8_t res;
    uint8_t opt_len;
    uint32_t data;
};
struct payload_h { 
};
struct ipaddrv4_h { 
    uint32_t addr;
};
struct ipaddrv6_h { 
    uint8_t addr[16];
};
union ipaddr_u { 
    struct ipaddrv4_h v4;
    struct ipaddrv6_h v6;
};
struct flowrec_s { 
    struct flowext_s * ext;
    struct timeval first;
    struct timeval last;
    uint64_t id;
    uint64_t parent;
    uint64_t bytes;
    uint32_t packets;
    uint8_t tcpflags;
    uint8_t ip_version;
    uint8_t tos;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    union ipaddr_u src_addr;
    union ipaddr_u dst_addr;
    uint64_t src_hwaddr;
    uint64_t dst_hwaddr;
};
struct http_request_h { 
    uint8_t method[10];
    uint8_t uri[128];
    uint8_t host[64];
    uint8_t referer[128];
    uint8_t agent[128];
};
struct http_response_h { 
    uint16_t code;
    uint8_t content_type[64];
};
union http_u { 
    struct http_request_h req;
    struct http_response_h resp;
};
struct http_extension_s { 
    uint8_t type;
    union http_u data;
};
struct tuple_0 { 
    uint8_t field_0;
    uint8_t field_1;
};
struct smtp_extension_s { 
    uint32_t code_2xx_cnt;
    uint32_t code_3xx_cnt;
    uint32_t code_4xx_cnt;
    uint32_t code_5xx_cnt;
    uint32_t command_flags;
    uint32_t mail_cmd_cnt;
    uint32_t mail_rcpt_cnt;
    uint32_t mail_code_flags;
    uint8_t domain[255];
    uint8_t first_sender[255];
    uint8_t first_recipient[255];
    uint8_t data_transfer;
};
struct https_extension_s { 
    uint8_t sni[255];
};
struct tls_rec_h { 
    uint8_t type;
    uint8_t v_major;
    uint8_t v_minor;
    uint16_t length;
};
struct tls_handshake_h { 
    uint8_t type;
    uint32_t length;
    uint8_t v_major;
    uint8_t v_minor;
};
struct tls_ext_h { 
    uint16_t type;
    uint16_t length;
};
struct tls_ext_sni_h { 
    uint8_t type;
    uint16_t length;
};
struct ntp_extension_s { 
    uint8_t li;
    uint8_t vn;
    uint8_t mode;
    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_id;
    uint64_t reference_ts;
    uint64_t origin_ts;
    uint64_t receive_ts;
    uint64_t transmit_ts;
};
struct sip_extension_s { 
    uint16_t msg_type;
    uint16_t status_code;
    uint8_t call_id[128];
    uint8_t calling_party[128];
    uint8_t called_party[128];
    uint8_t via[128];
    uint8_t user_agent[128];
    uint8_t cseq[128];
    uint8_t request_uri[128];
};

struct headers_s { 
    struct ethernet_h *eth;
    struct ipv4_h *ipv4;
    struct ipv6_h *ipv6;
    struct tcp_h *tcp;
    struct udp_h *udp;
    struct icmp_h *icmp;
    struct icmpv6_h *icmp6;
    struct payload_h *payload;
};

#endif
