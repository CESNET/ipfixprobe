/**
 * \file ntpplugin.cpp
 * \author Alejandro Robledo <robleale@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <string.h>

#include <unirec/unirec.h>

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "flow_meter.h"
#include "ntpplugin.h"
#include "packet.h"
#include "ipfix-elements.h"


using namespace std;

//#define DEBUG_NTP

/*Print debug message if debugging is allowed.*/
#ifdef DEBUG_NTP
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

#define NTP_UNIREC_TEMPLATE  "NTP_LEAP,NTP_VERSION,NTP_MODE,NTP_STRATUM,NTP_POLL,NTP_PRECISION,NTP_DELAY,NTP_DISPERSION,NTP_REF_ID,NTP_REF,NTP_ORIG,NTP_RECV,NTP_SENT"

UR_FIELDS (
   uint8 NTP_LEAP,
   uint8 NTP_VERSION
   uint8 NTP_MODE,
   uint8 NTP_STRATUM,
   uint8 NTP_POLL,
   uint8 NTP_PRECISION,
   uint32 NTP_DELAY,
   uint32 NTP_DISPERSION,
   string NTP_REF_ID,
   string NTP_REF,
   string NTP_ORIG,
   string NTP_RECV,
   string NTP_SENT
)

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
NTPPlugin::NTPPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   requests = 0;
   responses = 0;
   total = 0;
}

NTPPlugin::NTPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   requests = 0;
   responses = 0;
   total = 0;
}

/**
 *\brief Called after a new flow record is created.
 *\param [in,out] rec Reference to flow record.
 *\param [in] pkt Parsed packet.
 *\return 0 on success or FLOW_FLUSH option.
 */
int NTPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 123 || pkt.src_port == 123) {
      add_ext_ntp(rec, pkt);
      return FLOW_FLUSH;
   }

   return 0;
}

/**
 *\brief Called when everything is processed.
 */
void NTPPlugin::finish()
{
   if (print_stats) {
      cout << "NTP plugin stats:" << endl;
      cout << "   Parsed NTP requests: " << requests << endl;
      cout << "   Parsed NTP responses: " << responses << endl;
      cout << "   Total NTP packets processed: " << total << endl;
   }
}

/**
 *\brief Get unirec template string from plugin.
 *\return Unirec template string.
 */
string NTPPlugin::get_unirec_field_string()
{
   return NTP_UNIREC_TEMPLATE;
}
const char *ntp_ipfix_string[] = {
   IPFIX_NTP_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};
const char **NTPPlugin::get_ipfix_string()
{
   return ntp_ipfix_string;
}

/**
 *\brief Add new extension NTP header into Flow.
 *\param [in] packet.
 *\param [out] rec Destination Flow.
 */
void NTPPlugin::add_ext_ntp(Flow &rec, const Packet &pkt)
{
   RecordExtNTP *ntp_data_ext = new RecordExtNTP();
   if (!parse_ntp(pkt, ntp_data_ext)) {
      delete ntp_data_ext; /*Don't add new extension packet.*/
   } else {
      rec.addExtension(ntp_data_ext); /*Add extension to  packet.*/
   }
}

/**
 *\brief Parse and store NTP packet.
 *\param [in] Packet, and then take data Pointer to packet payload section.
 *\param [out] rec Output Flow extension header RecordExtNTP.
 *\return True if NTP was parsed.
 */
bool NTPPlugin::parse_ntp(const Packet &pkt, RecordExtNTP *ntp_data_ext)
{
   uint8_t i = 0;
   int number = 0, ch_counter = 0;
   const unsigned char *payload = NULL;
   unsigned char aux = '.';
   string result = "", result2 = "";
   ostringstream convert, convert2;
   string str;
   payload = (unsigned char *) pkt.payload;

   if (pkt.payload_length == 0) {
      DEBUG_MSG("Parser quits:\tpayload length = 0\n");
      return false; /*Don't add extension to  paket.*/
   }

   try{
      DEBUG_MSG("\n---------- NTP PARSER #%u ----------\n", total + 1);

      /******************
                 * PARSE NTP_LEAP.*
                 * ****************/
      total++;
      aux = payload[0];
      aux = aux >> 6;
      ntp_data_ext->leap = (uint8_t) aux;
      DEBUG_MSG("\tntp leap:\t\t%d\n", ntp_data_ext->leap);

      /*******************
                 *PARSE NTP_VERION.*
                 *******************/
      aux = payload[0];
      aux = aux << 2;
      aux = aux >> 5;
      ntp_data_ext->version = (uint8_t) aux;
      if (ntp_data_ext->version != 4) { throw "Error: Bad number of version or NTP exploit detected."; }
      DEBUG_MSG("\tntp version:\t\t%d\n", ntp_data_ext->version);

      /*****************
                 *PARSE NTP_MODE.*
       *****************/
      aux = payload[0];
      aux = aux << 5;
      aux = aux >> 5;
      ntp_data_ext->mode = (uint8_t) aux;
      if (ntp_data_ext->mode < 3 || ntp_data_ext->mode > 4) { throw "Error: Bad NTP mode or NTP exploit detected."; }
      if (ntp_data_ext->mode == 3) { requests++; }
      if (ntp_data_ext->mode == 4) { responses++; }
      DEBUG_MSG("\tntp mode:\t\t%d\n", ntp_data_ext->mode);

      /*********************
                 * PARSE NTP_STRATUM.*
                 * *******************/
      aux = payload[1];
      ntp_data_ext->stratum = (uint8_t) aux;
      if (ntp_data_ext->stratum > 16) { throw "Error: Bad NTP Stratum or NTP exploit detected."; }
      DEBUG_MSG("\tntp stratum:\t\t%d\n", ntp_data_ext->stratum);

      /*****************
      * PARSE NTP_POLL.*
      * ****************/
      aux = payload[2];
      ntp_data_ext->poll = (uint8_t) aux;
      if (ntp_data_ext->poll > 17) { throw "Error: Bad NTP Poll or NTP exploit detected."; }
      DEBUG_MSG("\tntp poll:\t\t%d\n", ntp_data_ext->poll);

      /*****************************************
      * PARSE NTP_PRECISION         not used   *
      ******************************************/
      aux = payload[3];
      ntp_data_ext->precision = (uint8_t) aux;
      DEBUG_MSG("\tntp precision:\t\t%d\n", ntp_data_ext->precision);

      /******************************************
      * PARSE NTP_DELAY-                        *
      *payload [4][5][6][7]. not implemented yet*
      *******************************************/

      /********************************************
      * PARSE NTP_DISPERSION-                     *
      *payload [8][9][10][11]. not implemented yet*
      *********************************************/

      /**************************
      * PARSE NTP_REF_ID -      *
      *payload [12][13][14][15].*
      ***************************/

      /********************************
      * First octect NTP reference ID.*
      * *******************************/
      ch_counter = 0;
      number = (int) payload[12];
      convert << number;
      result = convert.str();
      for (i = 0; i < convert.str().length(); i++) {
         ntp_data_ext->reference_id[ch_counter] = result[i];
         ch_counter++;
      }
      ntp_data_ext->reference_id[ch_counter] = '.';
      ch_counter++;
      result = "";
      stringstream ss;
      convert.str(".");

      /*********************************
      * Second octect NTP reference ID.*
      * ********************************/
      number = (int) payload[13];
      convert << number;
      result = convert.str();
      for (i = 0; i < convert.str().length(); i++) {
         ntp_data_ext->reference_id[ch_counter] = result[i];
         ch_counter++;
      }
      ntp_data_ext->reference_id[ch_counter] = '.';
      ch_counter++;
      result = "";
      convert.str(".");

      /********************************
      * Third octect NTP reference ID.*
      * *******************************/
      number = (int) payload[14];
      convert << number;
      result = convert.str();
      for (i = 0; i < convert.str().length(); i++) {
         ntp_data_ext->reference_id[ch_counter] = result[i];
         ch_counter++;
      }
      ntp_data_ext->reference_id[ch_counter] = '.';
      ch_counter++;
      result = "";
      convert.str(".");

      /*********************************
      * Fourth octect NTP reference ID.*
      * ********************************/
      number = (int) payload[15];
      convert << number;
      result = convert.str();
      for (i = 0; i < convert.str().length(); i++) {
         ntp_data_ext->reference_id[ch_counter] = result[i];
         ch_counter++;
      }
      ntp_data_ext->reference_id[ch_counter] = '\0';
      if (ntp_data_ext->stratum == 0) {
         if (strcmp (ntp_data_ext->reference_id, NTP_RefID_INIT) == 0) { strcpy (ntp_data_ext->reference_id, INIT); }
         if (strcmp (ntp_data_ext->reference_id, NTP_RefID_STEP) == 0) { strcpy (ntp_data_ext->reference_id, STEP); }
         if (strcmp (ntp_data_ext->reference_id, NTP_RefID_DENY) == 0) { strcpy (ntp_data_ext->reference_id, DENY); }
         if (strcmp (ntp_data_ext->reference_id, NTP_RefID_RATE) == 0) { strcpy (ntp_data_ext->reference_id, RATE); }
      }
      DEBUG_MSG("\tntp reference id:\t\t%s\n", ntp_data_ext->reference_id);

      /*****************************
      * PARSE NTP_REF -            *
      * payload:                   *
      * SECONDS   [16][17][18][19] *
      * FRACTIONS [20][21][22][23].*
      * ****************************/
      DEBUG_MSG("\tntp Reference Timestamp\n");
      ch_counter = 0;
      result = "";
      result = parse_timestamp(pkt, 16, 19, 20, 23);
      for (i = 0; i < result.length(); i++) {
         ntp_data_ext->reference[ch_counter] = result[i];
         ch_counter++;
      }
      ntp_data_ext->reference[ch_counter] = '\0';
      DEBUG_MSG("\t\ttimestamp:\t\t%s\n", ntp_data_ext->reference);

      /****************************
      * PARSE NTP_ORIG -          *
      *payload:                   *
      *SECONDS   [24][25][26][27] *
      *FRACTIONS [28][29][30][31].*
      *****************************/
      DEBUG_MSG("\tntp Origin Timestamp\n");
      ch_counter = 0;
      result = "";
      result = parse_timestamp(pkt, 24, 27, 28, 31);
      for (i = 0; i < result.length(); i++){
         ntp_data_ext->origin[ch_counter] = result[i];
         ch_counter++;
      }
      ntp_data_ext->origin[ch_counter] = '\0';
      DEBUG_MSG("\t\ttimestamp:\t\t%s\n", ntp_data_ext->origin);

      /****************************
      * PARSE NTP_RECV -          *
      *payload:                   *
      *SECONDS   [32][33][34][35] *
      *FRACTIONS [36][37][38][39].*
      *****************************/
      DEBUG_MSG("\tntp Receive Timestamp\n");
      ch_counter = 0;
      result = "";
      result = parse_timestamp(pkt, 32, 35, 36, 39);
      for(i = 0; i < result.length(); i++) {
         ntp_data_ext->receive[ch_counter] = result[i];
         ch_counter++;
      }
      ntp_data_ext->receive[ch_counter] = '\0';
      DEBUG_MSG("\t\ttimestamp:\t\t%s\n", ntp_data_ext->receive);

      /****************************
      * PARSE NTP_SENT -          *
      *payload:                   *
      *SECONDS   [40][41][42][43] *
      *FRACTIONS [44][45][46][47].*
      *****************************/
      DEBUG_MSG("\tntp Transmit Timestamp\n");
      ch_counter = 0;
      result = "";
      result = parse_timestamp(pkt, 40, 43, 44, 47);
      for (i = 0; i < result.length(); i++) {
         ntp_data_ext->sent[ch_counter] = result[i];
         ch_counter++;
      }
      ntp_data_ext->sent[ch_counter] = '\0';
      DEBUG_MSG("\t\ttimestamp:\t\t%s\n", ntp_data_ext->sent);

   } catch (const char *err) {
      DEBUG_MSG("%s\n", err);
      return false; /*Don't add extension to  paket.*/
   }

   return true; /*Add extension to  NTP packet*/
}

/**
*\brief Parse of Timestamp NTP packet.
*\param [in] Packet.
*\param [in] P1: Index of Payload where the First octect of the Seconds timestamp.
*\param [in] P4: Index of Payload where the Fourth octect of the Seconds timestamp.
*\param [in] P5: Index of Payload where the First octect of the Fraction timestamp starts.
*\param [in] P8: Index of Payload where the Fourth octect of the Fraction timestamp starts.
*\return String of timestamp.
*/
string NTPPlugin::parse_timestamp(const Packet &pkt, int p1, int p4, int p5, int p8)
{
   uint8_t i = 0, j = 0, k = 0;
   int number = 0;
   const unsigned char *payload = NULL;
   string result = "", result2 = "";
   ostringstream convert, convert2;
   string str;
   uint32_t time = 0;
   uint32_t highestbit = 0x80000000;
   float fract = 0.0f;
   uint32_t tmp = 0;
   float curfract = 0.5;
   payload = (unsigned char *) pkt.payload;

      /* ********************
      * SECONDS CALCULATION.*
      * *********************/
   result = "";
   convert.str("");
   number = 0;
   convert << 0;
   for (i = p1; i <= p4; i++) {
      number =  payload[i];
      convert << hex << number;
   }
   result = convert.str();
   str = result;
   const char *c = str.c_str();
   time = strtoul(c, 0, 16);
   convert2 << time;
   DEBUG_MSG("\t\ttimestamp seconds:\t\t\t%u\n", time);

      /* *********************
      * FRACTION CALCULATION.*
      * **********************/
   result = "";
   convert.str("");
   convert2 << ".";
   for (i = p5; i <= p8; i++) {
      number = payload[i];
      convert << number;
   }
   result = convert.str();
   str = result;
   const char *c2 = str.c_str();
   time = strtoul(c2, 0, 16);
   j = 0;
   tmp = time;
   for (i = 1; i <= 32; i++) {
      if ((highestbit & tmp) != 0) {
         fract = fract + curfract;
         j++;
      }
      curfract = curfract / 2;
      tmp = tmp << 1;
   }
   DEBUG_MSG("\t\ttimestamp fraction:\t\t\t%f\n", fract);
   convert2 << fract;
   result2 = convert2.str();
   j = 1;
   for(i = 0; j <= 1; i++) {
      if (result2[i] == '.') {
         j = 5;
         for (k = i + 2; k <= result2.length(); k++) { result2[k - 2] = result2[k]; }
      }
   }
   result2.resize(result2.length() - 1);
   return result2;
}

