/**
 * \file stacktrace.cpp
 * \brief Stack trace functions source file
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

#include <config.h>
#include <cxxabi.h>
#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "stacktrace.h"

void stacktrace_print(int sig)
{
   int framenum = 0;
   unw_context_t ctx;
   unw_cursor_t cursor;

   unw_getcontext(&ctx);
   unw_init_local(&cursor, &ctx);

   fprintf(stderr, "stacktrace dump of %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
#ifdef SYS_gettid
   fprintf(stderr, "pid: %d uid: %d\n", getpid(), getuid());
#else
   fprintf(stderr, "pid: %d tid: %d uid: %d\n", getpid(), gettid(), getuid());
#endif
   fprintf(stderr, "received signal: %d\n", sig);

   while (unw_step(&cursor) > 0) {
      unw_word_t offset;
      unw_word_t pc;
      unw_word_t sp;
      if (unw_get_reg(&cursor, UNW_REG_IP, &pc) == 0) {
         if (pc == 0) {
            break;
         }
         fprintf(stderr, "#%-3d %#016lx", framenum, pc);
      } else {
         fprintf(stderr, "#%-3d ???", framenum);
      }
      if (unw_get_reg(&cursor, UNW_REG_SP, &sp) == 0) {
         fprintf(stderr, " %#016lx", sp);
      } else {
         fprintf(stderr, " ???");
      }

      framenum++;
      printf(":");

      char sym[256];
      if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
         int status;
         char *nameptr = sym;
         char *demangled = abi::__cxa_demangle(sym, nullptr, nullptr, &status);
         if (status == 0) {
            nameptr = demangled;
         }
         fprintf(stderr, " %s+%#lx", nameptr, offset);
         if (unw_is_signal_frame(&cursor)) {
            fprintf(stderr, " <-");
         }
         fprintf(stderr, "\n");
         free(demangled);
      } else {
         fprintf(stderr, " ???\n");
      }
   }
}

