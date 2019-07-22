/**
 * \file plugin.h
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

#ifndef P4E_GENERATED_PLUGIN
#define P4E_GENERATED_PLUGIN

#include "types.h"
#include "cache.h"

#define PLUGINS_AVAILABLE "basic,http,smtp,https,ntp,sip"

enum parserResult {
   resultAccept = 0,
   resultReject = 1,
   resultFlush,
   resultExport
};

enum plugins { 
   flow_ext_http = 0,
   flow_ext_smtp,
   flow_ext_https,
   flow_ext_ntp,
   flow_ext_sip
};


int http_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len);
int smtp_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len);
int https_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len);
int ntp_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len);
int sip_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len);

int check_plugins_string(const char *plugins);
int add_plugins(struct flowcache_s *cache, const char *plugins);
void finish_plugins();

#endif
