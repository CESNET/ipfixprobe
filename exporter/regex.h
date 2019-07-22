/**
 * \file regex.h
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


int regex_http_292902314824198396(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len);
int regex_http_7657090775701301247(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len);
int regex_http_9954629388999303388(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len);
int regex_http_1241343039152043351(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_http_5218521091908217587(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_http_4336421465629048412(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_http_17001630350588684875(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_5548172357307236377(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_1003745245910973155(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len);
int regex_smtp_17189877207089016410(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len);
int regex_smtp_17179810292168586240(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_8038746631168771053(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_1491806206036761928(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_16043735937296782989(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len);
int regex_smtp_12378696050549599547(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_10049501445715452691(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len);
int regex_smtp_16154841742982731464(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_2926034056909831890(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len);
int regex_smtp_4356961479564686332(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_6311271132146768079(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_15599524012596978294(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_319042037054728586(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_4162994491442343091(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_17596464307372590331(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_10389749760020421673(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_14714683673343533196(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_7033087601884999626(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_11669751789635211030(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_smtp_5915433088431825607(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_https_1491806206036761928(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_6040635941264429671(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len);
int regex_sip_5462306868045633682(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_7275063398945298902(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len);
int regex_sip_16956443701230746937(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_18288776361479925058(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_4058077162105378156(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_18405895296614751714(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_12695820213868661575(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_16250651687722877417(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_12108815196634125945(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_958566060438879421(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_2244092928934076851(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_1352173392757520904(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_9954629388999303388(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor, uint8_t *arg0, size_t arg0_len, uint8_t *arg1, size_t arg1_len);
int regex_sip_4274360113148428379(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_14966057433110365877(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_5344484862863782926(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_5750864030914592696(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_5218521091908217587(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);
int regex_sip_14612721195332388417(const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor);