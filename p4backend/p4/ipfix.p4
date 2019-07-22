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

#ifndef _IPFIX_P4_
#define _IPFIX_P4_

#include "types.p4"

#define IPFIX_TEMPLATE_IPV4 0
#define IPFIX_TEMPLATE_IPV6 1
#define IPFIX_TEMPLATE_IPV4_HTTP 2
#define IPFIX_TEMPLATE_IPV6_HTTP 3
#define IPFIX_TEMPLATE_IPV4_SMTP 4
#define IPFIX_TEMPLATE_IPV6_SMTP 5
#define IPFIX_TEMPLATE_IPV4_HTTPS 6
#define IPFIX_TEMPLATE_IPV6_HTTPS 7
#define IPFIX_TEMPLATE_IPV4_NTP 8
#define IPFIX_TEMPLATE_IPV6_NTP 9
#define IPFIX_TEMPLATE_IPV4_SIP 10
#define IPFIX_TEMPLATE_IPV6_SIP 11

extern ipfix_exporter
{
   // choose template, must be called before adding any field
   void set_template(bit<8> id);
   void set_finish();

   // add field to the chosen template
   void add_field<H>(in H field);
   void add_field_empty();

   // register new template, must be called before adding any field
   // 4 fields are automatically added at the begin of template:
   // flow start, end msec timestamps and input interface
   void register_template(bit<8> id);

   // add field to template
   // format: enterprise number, element id, element length in bytes (only elements of fixed size supported yet)
   void add_template_field(bit<16> en, bit<16> id, int<16> len);
}

#define IPV4_TEMPLATE \
      e.add_template_field(0, 8, 4);   /* src ipv4    */\
      e.add_template_field(0, 12, 4);  /* dst ipv4    */\
      e.add_template_field(0, 60, 1);  /* l3 proto    */\
      e.add_template_field(0, 192, 1); /* ttl         */\
      e.add_template_field(0, 1, 8);   /* bytes       */\
      e.add_template_field(0, 2, 8);   /* packets     */\
      e.add_template_field(0, 4, 1);   /* l4 proto    */\
      e.add_template_field(0, 7, 2);   /* src por t   */\
      e.add_template_field(0, 11, 2);  /* dst port    */\
      e.add_template_field(0, 6, 1);   /* tcp flags   */\
      e.add_template_field(0, 56, 6);  /* src mac     */\
      e.add_template_field(0, 80, 6);  /* dst mac     */\

#define IPV6_TEMPLATE \
      e.add_template_field(0, 27, 16); /* src ipv6    */\
      e.add_template_field(0, 28, 16); /* dst ipv6    */\
      e.add_template_field(0, 60, 1);  /* l3 proto    */\
      e.add_template_field(0, 192, 1); /* ttl         */\
      e.add_template_field(0, 1, 8);   /* bytes       */\
      e.add_template_field(0, 2, 8);   /* packets     */\
      e.add_template_field(0, 4, 1);   /* l4 proto    */\
      e.add_template_field(0, 7, 2);   /* src por t   */\
      e.add_template_field(0, 11, 2);  /* dst port    */\
      e.add_template_field(0, 6, 1);   /* tcp flags   */\
      e.add_template_field(0, 56, 6);  /* src mac     */\
      e.add_template_field(0, 80, 6);  /* dst mac     */\

control exporter_init(ipfix_exporter e)
{
   apply {
      // IPV4
      e.register_template(IPFIX_TEMPLATE_IPV4);
      IPV4_TEMPLATE

      // IPV6
      e.register_template(IPFIX_TEMPLATE_IPV6);
      IPV6_TEMPLATE


      // IPV4 HTTP
      e.register_template(IPFIX_TEMPLATE_IPV4_HTTP);
      IPV4_TEMPLATE
      e.add_template_field(16982, 100, -1); // user agent
      e.add_template_field(16982, 101, -1); // method
      e.add_template_field(16982, 102, -1); // domain
      e.add_template_field(16982, 103, -1); // referer
      e.add_template_field(16982, 105, -1); // url
      e.add_template_field(16982, 104, -1); // content type
      e.add_template_field(16982, 106, 2); // status

      // IPV6 HTTP
      e.register_template(IPFIX_TEMPLATE_IPV6_HTTP);
      IPV6_TEMPLATE
      e.add_template_field(16982, 100, -1); // user agent
      e.add_template_field(16982, 101, -1); // method
      e.add_template_field(16982, 102, -1); // domain
      e.add_template_field(16982, 103, -1); // referer
      e.add_template_field(16982, 105, -1); // url
      e.add_template_field(16982, 104, -1); // content type
      e.add_template_field(16982, 106, 2); // status


      // IPV4 SMTP
      e.register_template(IPFIX_TEMPLATE_IPV4_SMTP);
      IPV4_TEMPLATE
      e.add_template_field(8057, 810,  4); // commands
      e.add_template_field(8057, 811,  4); // mail count
      e.add_template_field(8057, 812,  4); // rcpt count
      e.add_template_field(8057, 815,  4); // status codes
      e.add_template_field(8057, 816,  4); // 2xx count
      e.add_template_field(8057, 817,  4); // 3xx count
      e.add_template_field(8057, 818,  4); // 4xx count
      e.add_template_field(8057, 819,  4); // 5xx count
      e.add_template_field(8057, 820, -1); // domain
      e.add_template_field(8057, 813, -1); // sender
      e.add_template_field(8057, 814, -1); // recipients

      // IPV6 SMTP
      e.register_template(IPFIX_TEMPLATE_IPV6_SMTP);
      IPV6_TEMPLATE
      e.add_template_field(8057, 810,  4); // commands
      e.add_template_field(8057, 811,  4); // mail count
      e.add_template_field(8057, 812,  4); // rcpt count
      e.add_template_field(8057, 815,  4); // status codes
      e.add_template_field(8057, 816,  4); // 2xx count
      e.add_template_field(8057, 817,  4); // 3xx count
      e.add_template_field(8057, 818,  4); // 4xx count
      e.add_template_field(8057, 819,  4); // 5xx count
      e.add_template_field(8057, 820, -1); // domain
      e.add_template_field(8057, 813, -1); // sender
      e.add_template_field(8057, 814, -1); // recipients


      // IPV4 HTTPS
      e.register_template(IPFIX_TEMPLATE_IPV4_HTTPS);
      IPV4_TEMPLATE
      e.add_template_field(8057, 808, -1); // SNI

      // IPV6 HTTPS
      e.register_template(IPFIX_TEMPLATE_IPV6_HTTPS);
      IPV6_TEMPLATE
      e.add_template_field(8057, 808, -1); // SNI


      // IPV4 NTP
      e.register_template(IPFIX_TEMPLATE_IPV4_NTP);
      IPV4_TEMPLATE
      e.add_template_field(8057, 18, 1); // leap
      e.add_template_field(8057, 19, 1); // version
      e.add_template_field(8057, 20, 1); // mode
      e.add_template_field(8057, 21, 1); // stratum
      e.add_template_field(8057, 22, 1); // poll
      e.add_template_field(8057, 23, 1); // precision
      e.add_template_field(8057, 24, 4); // delay
      e.add_template_field(8057, 25, 4); // dispersion
      e.add_template_field(8057, 26, 4); // reference id
      e.add_template_field(8057, 27, 8); // reference ts
      e.add_template_field(8057, 28, 8); // original ts
      e.add_template_field(8057, 29, 8); // receive ts
      e.add_template_field(8057, 30, 8); // sent ts

      // IPV6 NTP
      e.register_template(IPFIX_TEMPLATE_IPV6_NTP);
      IPV6_TEMPLATE
      e.add_template_field(8057, 18, 1); // leap
      e.add_template_field(8057, 19, 1); // version
      e.add_template_field(8057, 20, 1); // mode
      e.add_template_field(8057, 21, 1); // stratum
      e.add_template_field(8057, 22, 1); // poll
      e.add_template_field(8057, 23, 1); // precision
      e.add_template_field(8057, 24, 4); // delay
      e.add_template_field(8057, 25, 4); // dispersion
      e.add_template_field(8057, 26, 4); // reference id
      e.add_template_field(8057, 27, 8); // reference ts
      e.add_template_field(8057, 28, 8); // original ts
      e.add_template_field(8057, 29, 8); // receive ts
      e.add_template_field(8057, 30, 8); // sent ts


      // IPV4 SIP
      e.register_template(IPFIX_TEMPLATE_IPV4_SIP);
      IPV4_TEMPLATE
      e.add_template_field(8057, 100, 2); // msg type
      e.add_template_field(8057, 101, 2); // status code
      e.add_template_field(8057, 102, -1); // call id
      e.add_template_field(8057, 103, -1); // calling party
      e.add_template_field(8057, 104, -1); // called party
      e.add_template_field(8057, 105, -1); // via
      e.add_template_field(8057, 106, -1); // user agent
      e.add_template_field(8057, 107, -1); // request uri
      e.add_template_field(8057, 108, -1); // cseq

      // IPV6 SIP
      e.register_template(IPFIX_TEMPLATE_IPV6_SIP);
      IPV6_TEMPLATE
      e.add_template_field(8057, 100, 2); // msg type
      e.add_template_field(8057, 101, 2); // status code
      e.add_template_field(8057, 102, -1); // call id
      e.add_template_field(8057, 103, -1); // calling party
      e.add_template_field(8057, 104, -1); // called party
      e.add_template_field(8057, 105, -1); // via
      e.add_template_field(8057, 106, -1); // user agent
      e.add_template_field(8057, 107, -1); // request uri
      e.add_template_field(8057, 108, -1); // cseq
   }
}

      //e.add_field(flow.tos);
#define FILL_IPFIX_TEMPLATE(tmplt1, tmplt2) \
      if (flow.ip_version == 4) {\
         e.set_template(tmplt1);\
         e.add_field(flow.src_addr.v4.addr);\
         e.add_field(flow.dst_addr.v4.addr);\
      } else {\
         e.set_template(tmplt2);\
         e.add_field(flow.src_addr.v6.addr);\
         e.add_field(flow.dst_addr.v6.addr);\
      }\
      e.add_field(flow.ip_version);\
      e.add_field(flow.ttl);\
      e.add_field(flow.bytes);\
      e.add_field((bit<64>)flow.packets);\
      e.add_field(flow.protocol);\
      e.add_field(flow.src_port);\
      e.add_field(flow.dst_port);\
      e.add_field(flow.tcpflags);\
      e.add_field(flow.src_hwaddr);\
      e.add_field(flow.dst_hwaddr);\

control exporter_export(in flowrec_s flow, ipfix_exporter e)
{
   apply {
      FILL_IPFIX_TEMPLATE(IPFIX_TEMPLATE_IPV4, IPFIX_TEMPLATE_IPV6);
      e.set_finish();
   }
}

#endif // _IPFIX_P4_
