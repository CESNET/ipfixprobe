#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include <ipfixprobe/packet.hpp>

// IPv6 address is 128 bits = 16 bytes
#define IP6_ADDR_LEN 16
#define MAX_CIDER_NETS 10
#define MAX_CIDER_EXLUDE 10

typedef struct {
    int family;
    union {
        uint32_t      v4;               // host byte order
        unsigned char v6[IP6_ADDR_LEN]; // binary form (network byte order usually, but we use host for simplicity)
    } addr;
    union {
        uint32_t      v4_mask;          // host byte order
        unsigned char v6_mask[IP6_ADDR_LEN];
    } mask;
} cidr_mask;

typedef struct {
    cidr_mask cidr;
    cidr_mask cidr_exlude[MAX_CIDER_EXLUDE];
} cidr_nets;

typedef enum {
    MODE_NONE = -1,
    MODE_SRC = 1,
    MODE_DST = 2
} source_optimization_mode_t;

class SourceOptimization {
  public:
    uint8_t net_count;
    cidr_nets nets[MAX_CIDER_NETS];
    SourceOptimization();
    SourceOptimization(std::vector<std::string>& vnets); 
    bool cidr_to_mask(const char *cidr_str, cidr_mask& out);
    bool ip_in_cidr(const char *ip_str, const cidr_mask& cidr);
    bool ip_in_cidr(uint32_t ipv4, const cidr_mask& cidr);
    bool ip_in_cidr(unsigned char ipv6[IP6_ADDR_LEN], const cidr_mask& cidr);
    int ip_to_binary(const char *ip_str, unsigned char *out_buf, size_t buf_len);
    source_optimization_mode_t get_mode(ipxp::Packet& pkt);
};
