#ifndef NFBREADER_C_H
#define NFBREADER_C_H

#include <stdint.h>
#include "ndpheader.h"

#ifdef __cplusplus
extern "C" {
#endif

struct NdpReaderContext {
	void *reader;
};

extern void ndp_reader_init(struct NdpReaderContext* context);
extern void ndp_reader_free(struct NdpReaderContext* context);
extern const char *ndp_reader_error_msg(struct NdpReaderContext* context);
extern int  ndp_reader_init_interface(struct NdpReaderContext* context, const char *interface);
extern void ndp_reader_print_stats(struct NdpReaderContext* context);
extern void ndp_reader_close(struct NdpReaderContext* context);
extern int  ndp_reader_get_pkt(struct NdpReaderContext* context, struct ndp_packet **ndp_packet, struct ndp_header **ndp_header);

#ifdef __cplusplus
}
#endif

#endif //NFBREADER_C_H
