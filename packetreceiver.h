/**
 * \file packetreceiver.h
 * \brief Generic interface of pacekt receiver (PacketReceiver class)
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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

#ifndef PACKETRECEIVER_H
#define PACKETRECEIVER_H

#include <string>

#include "packet.h"

using namespace std;

/**
 * \brief Base class for packet receivers.
 */
class PacketReceiver
{
public:

   virtual ~PacketReceiver() {}
   virtual int open_file(const string &file, bool parse_every_pkt) = 0;
   virtual int init_interface(const string &interface, int snaplen, bool parse_every_pkt) = 0;
   virtual int set_filter(const string &filter_str) = 0;
   virtual void printStats() = 0;
   virtual void close() = 0;

   string error_msg; /**< String to store an error messages. */

   /**
    * \brief Get packet from network interface or file.
    * \param [out] packet Variable for storing parsed packet.
    * \return 2 if packet was parsed and stored, 1 if packet was not parsed, 3 when read timeout occur,
    *         0 if EOF or value < 0 on error
    */
   virtual int get_pkt(Packet &packet) = 0;
};

#endif
