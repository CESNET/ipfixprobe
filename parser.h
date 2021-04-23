/**
 * \file parser.h
 * \brief Packet parser functions
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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

#ifndef PARSER_H
#define PARSER_H

#include "packet.h"

#ifndef ETH_P_8021AD
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN*/
#endif

#ifndef ETH_P_TRILL
#define ETH_P_TRILL	0x22F3          /* TRILL protocol */
#endif

typedef struct parser_opt_s {
   PacketBlock *pkts;
   bool packet_valid;
   bool parse_all;
   int datalink;
} parser_opt_t;

void parse_packet(parser_opt_t *opt, struct timeval ts, const uint8_t *data, uint16_t len, uint16_t caplen);

#endif /* PARSER_H */
