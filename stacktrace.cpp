/**
 * \file stacktrace.cpp
 * \brief Stack trace functions source file
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
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "stacktrace.hpp"

namespace ipxp {

static void st_write(int fd, const char *buffer, size_t buflen)
{
   size_t total = 0;
   while (total < buflen) {
      ssize_t written = write(fd, buffer + total, buflen - total);
      if (written < 0) {
         return;
      }

      total += written;
   }
}

static void st_write_str(int fd, const char *str)
{
   st_write(fd, str, strlen(str));
}

static void st_write_num(int fd, int num, int padding=0)
{
   char buf[22];
   int idx = 0;
   int tmp = num < 0 ? -num : num;

   if (num == 0) {
      buf[idx++] = '0';
   }

   while (tmp != 0) {
      buf[idx++] = '0' + tmp % 10;
      tmp /= 10;
   }
   if (num < 0) {
      buf[idx++] = '-';
   }

   for (int i = 0; i < idx / 2; i++) {
      char tmp = buf[i];
      buf[i] = buf[idx - i - 1];
      buf[idx - i - 1] = tmp;
   }
   while (idx < padding) {
         buf[idx++] = ' ';
   }
   buf[idx] = 0;

   st_write_str(fd, buf);
}

static char nibble2hex(uint8_t num)
{
   if (num < 10) {
      return '0' + num;
   } else if (num < 16) {
      return 'a' + num - 10;
   }
   return '?';
}

static void st_write_num_hex(int fd, uint64_t num, size_t size, bool nopad=false)
{
   char buf[19] = "0x";
   bool nonzero_seen = false;
   size_t idx = 2;

   for (int i = 0; i < (int) size; i++) {
      uint8_t bits2shift = (size - i - 1) * size;
      uint8_t byte = (num >> bits2shift) & 0xFF;
      if (byte == 0 && nopad && !nonzero_seen) {
         continue;
      }
      buf[idx]     = nibble2hex(byte >> 4);
      buf[idx + 1] = nibble2hex(byte & 0x0F);
      idx += 2;
      nonzero_seen = true;
   }
   buf[idx] = 0;
   st_write_str(fd, buf);
}

static void st_write_word(int fd, unw_word_t num, bool nopad=false)
{
   st_write_num_hex(fd, num, sizeof(num), nopad);
}

void st_dump(int fd, int sig)
{
   int framenum = 0;
   unw_context_t ctx;
   unw_cursor_t cursor;

   unw_getcontext(&ctx);
   unw_init_local(&cursor, &ctx);

   st_write_str(fd, "stacktrace dump of " PACKAGE_NAME " " PACKAGE_VERSION "\n");
   st_write_str(fd, "uid: ");
   st_write_num(fd, getuid());
   st_write_str(fd, " pid: ");
   st_write_num(fd, getpid());
#ifdef SYS_gettid
   st_write_str(fd, " tid: ");
   st_write_num(fd, syscall(SYS_gettid));
#endif
   st_write_str(fd, "\n");

   st_write_str(fd, "received signal: ");
   st_write_num(fd, sig);
   st_write_str(fd, "\n");


   while (unw_step(&cursor) > 0) {
      unw_word_t offset;
      unw_word_t pc;
      unw_word_t sp;

      st_write_str(fd, "#");
      st_write_num(fd, framenum, 2);
      st_write_str(fd, " ");
      if (unw_get_reg(&cursor, UNW_REG_IP, &pc) == 0) {
         if (pc == 0) {
            break;
         }

         st_write_word(fd, pc);
      } else {
         st_write_str(fd, "???");
      }
      st_write_str(fd, " ");
      if (unw_get_reg(&cursor, UNW_REG_SP, &sp) == 0) {
         st_write_word(fd, sp);
      } else {
         st_write_str(fd, "???");
      }

      framenum++;
      st_write_str(fd, ": ");

      char sym[256];
      if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
         st_write_str(fd, sym);
         st_write_str(fd, "+");
         st_write_word(fd, offset, true);
         if (unw_is_signal_frame(&cursor)) {
            st_write_str(fd, " <-");
         }
         st_write_str(fd, "\n");
      } else {
         st_write_str(fd, "???\n");
      }
   }
}

}
