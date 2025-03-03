/**
 * \file stats.cpp
 * \brief Implementation of service IO functions, modified code from libtrap service ifc and trap_stats
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
 *
 *
 */

#include <config.h>
#include <string>

#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "stats.hpp"

namespace ipxp
{

int connect_to_exporter(const char *path)
{
   int fd;
   struct sockaddr_un addr;

   memset(&addr, 0, sizeof(addr));
   addr.sun_family = AF_UNIX;
   snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s", path);

   fd = socket(AF_UNIX, SOCK_STREAM, 0);
   if (fd != -1) {
      if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
         perror("unable to connect");
         close(fd);
         return -1;
      }
   }
   return fd;
}

int create_stats_sock(const char *path)
{
   int fd;
   struct sockaddr_un addr;

   addr.sun_family = AF_UNIX;
   snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s", path);

   unlink(addr.sun_path);
   fd = socket(AF_UNIX, SOCK_STREAM, 0);
   if (fd != -1) {
      if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
         perror("unable to bind socket");
         close(fd);
         return -1;
      }
      if (listen(fd, 1) == -1) {
         perror("unable to listen on socket");
         close(fd);
         return -1;
      }
      if (chmod(addr.sun_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) == -1) {
         perror("unable to set access rights");
         close(fd);
         return -1;
      }
   }
   return fd;
}

int recv_data(int fd, uint32_t size, void *data)
{
   size_t num_of_timeouts = 0;
   size_t total_received = 0;
   ssize_t last_received = 0;

   while (total_received < size) {
      last_received = recv(fd, (uint8_t *) data + total_received, size - total_received, MSG_DONTWAIT);
      if (last_received == 0) {
         return -1;
      } else if (last_received == -1) {
         if (errno == EAGAIN  || errno == EWOULDBLOCK) {
            num_of_timeouts++;
            if (num_of_timeouts > SERVICE_WAIT_MAX_TRY) {
               return -1;
            } else {
               usleep(SERVICE_WAIT_BEFORE_TIMEOUT);
               continue;
            }
         }
         return -1;
      }
      total_received += last_received;
   }
   return 0;
}

int send_data(int fd, uint32_t size, void *data)
{
   size_t num_of_timeouts = 0;
   size_t total_sent = 0;
   ssize_t last_sent = 0;

   while (total_sent < size) {
      last_sent = send(fd, (uint8_t *) data + total_sent, size - total_sent, MSG_DONTWAIT);
      if (last_sent == -1) {
         if (errno == EAGAIN  || errno == EWOULDBLOCK) {
            num_of_timeouts++;
            if (num_of_timeouts > SERVICE_WAIT_MAX_TRY) {
               return -1;
            } else {
               usleep(SERVICE_WAIT_BEFORE_TIMEOUT);
               continue;
            }
         }
         return -1;
      }
      total_sent += last_sent;
   }
   return 0;
}

std::string create_sockpath(const char *id)
{
   return DEFAULTSOCKETDIR "/ipfixprobe_" + std::string(id) + ".sock";
}

}
