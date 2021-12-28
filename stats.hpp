/**
 * \file stats.hpp
 * \brief Exporter stats definition and service IO functions
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
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
 *
 */

#ifndef IPXP_STATS_HPP
#define IPXP_STATS_HPP

#define SERVICE_WAIT_BEFORE_TIMEOUT 250000  ///< Timeout after EAGAIN or EWOULDBLOCK errno returned from service send() and recv().
#define SERVICE_WAIT_MAX_TRY 8  ///< A maximal count of repeated timeouts per each service recv() and send() function call.

#define MSG_MAGIC 0xBEEFFEEB

namespace ipxp
{

struct InputStats {
   uint64_t packets;
   uint64_t parsed;
   uint64_t bytes;
   uint64_t qtime;
   uint64_t dropped;
};

struct OutputStats {
   uint64_t biflows;
   uint64_t bytes;
   uint64_t packets;
   uint64_t dropped;
};

typedef struct msg_header_s
{
   uint32_t magic;
   uint16_t size;
   uint16_t inputs;
   uint16_t outputs;

   // followed by arrays of plugin stats
} msg_header_t;

int connect_to_exporter(const char *path);
int create_stats_sock(const char *path);
int recv_data(int sd, uint32_t size, void *data);
int send_data(int sd, uint32_t size, void *data);
std::string create_sockpath(const char *id);

}
#endif /* IPXP_STATS_HPP */
