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

#ifndef _NTP_PLUGIN_P4_
#define _NTP_PLUGIN_P4_

#include <core.p4>
#include "types.p4"
#include "ipfix.p4"
#include "plugin.p4"

header ntp_extension_s
{
   bit<2> li;
   bit<3> vn;
   bit<3> mode;
   bit<8> stratum;
   bit<8> poll;
   bit<8> precision;
   bit<32> root_delay;
   bit<32> root_dispersion;
   bit<32> reference_id;

   bit<64> reference_ts;
   bit<64> origin_ts;
   bit<64> receive_ts;
   bit<64> transmit_ts;
}

parser ntp_plugin_parser(payload p, out ntp_extension_s ext)
{
   state start {
      p.extract(ext);
      transition parse_ntp_check_version;
   }
   state parse_ntp_check_version {
      transition select(ext.vn) {
         3w0x4: parse_ntp_check_mode;
         default: reject;
      }
   }
   state parse_ntp_check_mode {
      transition select(ext.mode) {
         3: parse_ntp_check_stratum;
         4: parse_ntp_check_stratum;
         default: reject;
      }
   }
   state parse_ntp_check_stratum {
      transition select(ext.stratum > 16) {
         true: reject;
         false: parse_ntp_check_poll;
      }
   }
   state parse_ntp_check_poll {
      transition select(ext.stratum > 17) {
         true: reject;
         false: flush;
      }
   }
   state flush {
      transition accept;
   }
}

control ntp_plugin_export(in flowrec_s flow, in ntp_extension_s ext, ipfix_exporter e)
{
   apply {
      FILL_IPFIX_TEMPLATE(IPFIX_TEMPLATE_IPV4_NTP, IPFIX_TEMPLATE_IPV6_NTP);
      e.add_field(ext.li);
      e.add_field(ext.vn);
      e.add_field(ext.mode);
      e.add_field(ext.stratum);
      e.add_field(ext.poll);
      e.add_field(ext.precision);
      e.add_field(ext.root_delay);
      e.add_field(ext.root_dispersion);
      e.add_field(ext.reference_id);
      e.add_field(ext.reference_ts);
      e.add_field(ext.origin_ts);
      e.add_field(ext.receive_ts);
      e.add_field(ext.transmit_ts);
      e.set_finish();
   }
}

#endif