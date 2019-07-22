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

#include "headers.p4"
#include "types.p4"

#include "parser.p4"
#include "cache.p4"
#include "ipfix.p4"

#include "http_plugin.p4"
#include "smtp_plugin.p4"
#include "https_plugin.p4"
#include "ntp_plugin.p4"
#include "sip_plugin.p4"

// Parser
parser parse_packet(packet_in packet, out headers_s headers);

// Cache
control cache_create_flow(in headers_s headers, flowcache c, out flowrec_s flow, out bool success);
control cache_update_flow(in headers_s headers, flowcache c, out flowrec_s flow);

// Exporter
control exporter_init_templates(ipfix_exporter e);
control exporter_export_flow(in flowrec_s rec, ipfix_exporter e);

// HTTP plugin
parser http_plugin_create_(payload p, out http_extension_s ext);
parser http_plugin_update_(payload p, out http_extension_s ext);
control http_plugin_export_(in flowrec_s flow, in http_extension_s ext, ipfix_exporter e);
package http_plugin(http_plugin_create_ create, http_plugin_update_ update, http_plugin_export_ export);

// SMTP plugin
parser smtp_plugin_create_(payload p, in flowrec_s flow, out smtp_extension_s ext);
parser smtp_plugin_update_(payload p, in flowrec_s flow, out smtp_extension_s ext);
control smtp_plugin_export_(in flowrec_s flow, in smtp_extension_s ext, ipfix_exporter e);
package smtp_plugin(smtp_plugin_create_ create, smtp_plugin_update_ update, smtp_plugin_export_ export);

// HTTPS plugin
parser https_plugin_create_(payload p, out https_extension_s ext);
parser https_plugin_update_(payload p, out https_extension_s ext);
control https_plugin_export_(in flowrec_s flow, in https_extension_s ext, ipfix_exporter e);
package https_plugin(https_plugin_create_ create, https_plugin_update_ update, https_plugin_export_ export);

// NTP plugin
parser  ntp_plugin_create_(payload p, out ntp_extension_s ext);
parser  ntp_plugin_update_(payload p, out ntp_extension_s ext);
control ntp_plugin_export_(in flowrec_s flow, in ntp_extension_s ext, ipfix_exporter e);
package ntp_plugin(ntp_plugin_create_ create, ntp_plugin_update_ update, ntp_plugin_export_ export);

// SIP plugin
parser sip_plugin_create_(payload p, out sip_extension_s ext);
parser sip_plugin_update_(payload p, out sip_extension_s ext);
control sip_plugin_export_(in flowrec_s flow, in sip_extension_s ext, ipfix_exporter e);
package sip_plugin(sip_plugin_create_ create, sip_plugin_update_ update, sip_plugin_export_ export);

// plugins
package cache_plugins(http_plugin http, smtp_plugin smtp, https_plugin https, ntp_plugin ntp, sip_plugin sip);

// Top package
package top(parse_packet prs,
   cache_create_flow create, cache_update_flow update,
   exporter_init_templates init, exporter_export_flow export,
   cache_plugins plugins
);

cache_plugins(
   http_plugin(http_plugin_parser(), http_plugin_parser(), http_plugin_export()),
   smtp_plugin(smtp_plugin_parser(), smtp_plugin_parser(), smtp_plugin_export()),
   https_plugin(https_plugin_parser(), https_plugin_parser(), https_plugin_export()),
   ntp_plugin(ntp_plugin_parser(), ntp_plugin_parser(), ntp_plugin_export()),
   sip_plugin(sip_plugin_parser(), sip_plugin_parser(), sip_plugin_export())
) plugins;
top(prs(), flow_create(), flow_update(), exporter_init(), exporter_export(), plugins) main;
