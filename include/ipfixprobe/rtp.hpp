#include <inttypes.h>
#include <limits>

struct __attribute__((packed)) rtp_header {
    union {
        struct {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
            uint16_t csrc_count : 4;
            uint16_t extension : 1;
            uint16_t padding : 1;
            uint16_t version : 2;
            // next byte
            uint16_t payload_type : 7;
            uint16_t marker : 1;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
            uint16_t version : 2;
            uint16_t padding : 1;
            uint16_t extension : 1;
            uint16_t csrc_count : 4;
            // next byte
            uint16_t marker : 1;
            uint16_t payload_type : 7;

#else // if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
#error "Please fix <endian.h>"
#endif // if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
        };
        uint16_t flags;
    };
    uint16_t sequence_number;
    uint32_t timestamp;
    uint32_t ssrc;
};