/**
 * \file regex.c
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "regex.h"


int regex_http_292902314824198396(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 3;
   const uint8_t *yypmatch[6];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   const uint8_t *yyt3;
   (void) yyt1;
   (void) yyt2;
   (void) yyt3;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      ("GET"|"POST"|"PUT"|"HEAD"|"DELETE"|"TRACE"|"OPTIONS"|"CONNECT"|"PATCH")[ ]([^ ]*)[ ]"HTTP"[/][0-9][.][0-9]"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         len = yypmatch[5] - yypmatch[4];
         if (len >= arg1_len) {
            len = arg1_len - 1;
         }
         memcpy(arg1, yypmatch[4], len);
         arg1[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_http_7657090775701301247(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "HTTP"[/][0-9][.][0-9][ ]([0-9]*)[ ].*"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_http_9954629388999303388(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 3;
   const uint8_t *yypmatch[6];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   const uint8_t *yyt3;
   (void) yyt1;
   (void) yyt2;
   (void) yyt3;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      ([^:]*)": "(.*)"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         len = yypmatch[5] - yypmatch[4];
         if (len >= arg1_len) {
            len = arg1_len - 1;
         }
         memcpy(arg1, yypmatch[4], len);
         arg1[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_http_1241343039152043351(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "Host\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_http_5218521091908217587(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "User-Agent\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_http_4336421465629048412(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "Referer\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_http_17001630350588684875(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "Content-Type\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_5548172357307236377(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 1;
   const uint8_t *yypmatch[2];
   const uint8_t *yyt1;
   (void) yyt1;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      ".\r\n" {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_1003745245910973155(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 3;
   const uint8_t *yypmatch[6];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   const uint8_t *yyt3;
   (void) yyt1;
   (void) yyt2;
   (void) yyt3;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      ([A-Za-z]{4,})([ ]|"\r\n") {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         len = yypmatch[5] - yypmatch[4];
         if (len >= arg1_len) {
            len = arg1_len - 1;
         }
         memcpy(arg1, yypmatch[4], len);
         arg1[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_smtp_17189877207089016410(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 3;
   const uint8_t *yypmatch[6];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   const uint8_t *yyt3;
   (void) yyt1;
   (void) yyt2;
   (void) yyt3;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      ([0-9]{3})([ -]) {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         len = yypmatch[5] - yypmatch[4];
         if (len >= arg1_len) {
            len = arg1_len - 1;
         }
         memcpy(arg1, yypmatch[4], len);
         arg1[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_smtp_17179810292168586240(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'HELO\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_8038746631168771053(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'EHLO\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_1491806206036761928(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_16043735937296782989(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      (.*)"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_smtp_12378696050549599547(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'RCPT\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_10049501445715452691(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'TO: '(.*)"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_smtp_16154841742982731464(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'MAIL\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_2926034056909831890(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'FROM: '(.*)"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_smtp_4356961479564686332(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'DATA\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_6311271132146768079(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'VRFY\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_15599524012596978294(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'EXPN\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_319042037054728586(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'HELP\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_4162994491442343091(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'NOOP\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_17596464307372590331(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      'QUIT\x00' {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_10389749760020421673(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "2" {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_14714683673343533196(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "3" {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_7033087601884999626(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "4" {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_11669751789635211030(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "5" {
      return 1;
   }
   */
   return 0;
}

int regex_smtp_5915433088431825607(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 1;
   const uint8_t *yypmatch[2];
   const uint8_t *yyt1;
   (void) yyt1;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      .*'SPAM' {
      return 1;
   }
   */
   return 0;
}

int regex_https_1491806206036761928(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_6040635941264429671(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 3;
   const uint8_t *yypmatch[6];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   const uint8_t *yyt3;
   (void) yyt1;
   (void) yyt2;
   (void) yyt3;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      ("REGISTER"|"INVITE"|"ACK"|"BYE"|"CANCEL"|"UPDATE"|"REFER"|"PRACK"|"SUBSCRIBE"|"NOTIFY"|"PUBLISH"|"MESSAGE"|"INFO"|"OPTIONS")[ ]([^ ]*)[ ]"SIP"[/][0-9][.][0-9]"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         len = yypmatch[5] - yypmatch[4];
         if (len >= arg1_len) {
            len = arg1_len - 1;
         }
         memcpy(arg1, yypmatch[4], len);
         arg1[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_sip_5462306868045633682(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "INVITE\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_7275063398945298902(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "SIP"[/][0-9][.][0-9][ ]([0-9]*)[ ].*"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_sip_16956443701230746937(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "ACK\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_18288776361479925058(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "CANCEL\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_4058077162105378156(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "BYE\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_18405895296614751714(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "REGISTER\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_12695820213868661575(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "OPTIONS\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_16250651687722877417(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "PUBLISH\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_12108815196634125945(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "NOTIFY\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_958566060438879421(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "INFO\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_2244092928934076851(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "SUBSCRIBE\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_1352173392757520904(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "STATUS\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_9954629388999303388(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 3;
   const uint8_t *yypmatch[6];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   const uint8_t *yyt3;
   (void) yyt1;
   (void) yyt2;
   (void) yyt3;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      ([^:]*)": "(.*)"\r\n" {
         size_t len;
         len = yypmatch[3] - yypmatch[2];
         if (len >= arg0_len) {
            len = arg0_len - 1;
         }
         memcpy(arg0, yypmatch[2], len);
         arg0[len] = 0;
         len = yypmatch[5] - yypmatch[4];
         if (len >= arg1_len) {
            len = arg1_len - 1;
         }
         memcpy(arg1, yypmatch[4], len);
         arg1[len] = 0;
         *payload_cursor = payload;
         return 1;
      }
   */
   return 0;
}

int regex_sip_4274360113148428379(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "From\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_14966057433110365877(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "To\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_5344484862863782926(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "Via\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_5750864030914592696(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "Call-ID\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_5218521091908217587(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "User-Agent\x00" {
      return 1;
   }
   */
   return 0;
}

int regex_sip_14612721195332388417(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor)
{ 
   const uint8_t *backup;
   const uint8_t *marker;
   int yynmatch = 2;
   const uint8_t *yypmatch[4];
   const uint8_t *yyt1;
   const uint8_t *yyt2;
   (void) yyt1;
   (void) yyt2;
   (void) backup;
   (void) marker;
   (void) yynmatch;
   (void) yypmatch;
   #  define YYCTYPE     uint8_t
   #  define YYPEEK()    (payload < payload_end ? *payload : 0)
   #  define YYSKIP()    ++payload
   #  define YYFILL(n)   return 0;
   #  define YYCURSOR    payload
   #  define YYLIMIT     payload_end
   #  define YYMARKER    marker
   #  define YYBACKUP()  backup = payload
   #  define YYRESTORE() payload = backup
   /*!re2c
      * { return 0; }
      "CSeq\x00" {
      return 1;
   }
   */
   return 0;
}

