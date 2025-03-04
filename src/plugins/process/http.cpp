/**
 * \file http.cpp
 * \brief Plugin for parsing HTTP traffic
 * \author Jiri Havranek <havranek@cesnet.cz>
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
 *
 *
 */

#include <cstdlib>
#include <cstring>
#include <iostream>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "common.hpp"
#include "http.hpp"

namespace ipxp {

int RecordExtHTTP::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
	static PluginRecord rec = PluginRecord("http", []() { return new HTTPPlugin(); });
	register_plugin(&rec);
	RecordExtHTTP::REGISTERED_ID = register_extension();
}

// #define DEBUG_HTTP

// Print debug message if debugging is allowed.
#ifdef DEBUG_HTTP
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_HTTP
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

#define HTTP_LINE_DELIMITER "\r\n"
#define HTTP_KEYVAL_DELIMITER ':'
#define HTTP_SETCOOKIE_NAME_DELIMITER "="
#define STRING_DELIMITER ";"

HTTPPlugin::HTTPPlugin()
	: recPrealloc(nullptr)
	, flow_flush(false)
	, requests(0)
	, responses(0)
	, total(0)
{
}

HTTPPlugin::~HTTPPlugin()
{
	close();
}

void HTTPPlugin::init(const char* params) {}

void HTTPPlugin::close()
{
	if (recPrealloc != nullptr) {
		delete recPrealloc;
		recPrealloc = nullptr;
	}
}

ProcessPlugin* HTTPPlugin::copy()
{
	return new HTTPPlugin(*this);
}

int HTTPPlugin::post_create(Flow& rec, const Packet& pkt)
{
	const char* payload = reinterpret_cast<const char*>(pkt.payload);
	if (is_request(payload, pkt.payload_len)) {
		add_ext_http_request(payload, pkt.payload_len, rec);
	} else if (is_response(payload, pkt.payload_len)) {
		add_ext_http_response(payload, pkt.payload_len, rec);
	}

	return 0;
}

int HTTPPlugin::pre_update(Flow& rec, Packet& pkt)
{
	RecordExt* ext = nullptr;
	const char* payload = reinterpret_cast<const char*>(pkt.payload);
	if (is_request(payload, pkt.payload_len)) {
		ext = rec.get_extension(RecordExtHTTP::REGISTERED_ID);
		if (ext == nullptr) { /* Check if header is present in flow. */
			add_ext_http_request(payload, pkt.payload_len, rec);
			return 0;
		}

		parse_http_request(payload, pkt.payload_len, static_cast<RecordExtHTTP*>(ext));
		if (flow_flush) {
			flow_flush = false;
			return FLOW_FLUSH_WITH_REINSERT;
		}
	} else if (is_response(payload, pkt.payload_len)) {
		ext = rec.get_extension(RecordExtHTTP::REGISTERED_ID);
		if (ext == nullptr) { /* Check if header is present in flow. */
			add_ext_http_response(payload, pkt.payload_len, rec);
			return 0;
		}

		parse_http_response(payload, pkt.payload_len, static_cast<RecordExtHTTP*>(ext));
		if (flow_flush) {
			flow_flush = false;
			return FLOW_FLUSH_WITH_REINSERT;
		}
	}

	return 0;
}

void HTTPPlugin::finish(bool print_stats)
{
	if (print_stats) {
		std::cout << "HTTP plugin stats:" << std::endl;
		std::cout << "   Parsed http requests: " << requests << std::endl;
		std::cout << "   Parsed http responses: " << responses << std::endl;
		std::cout << "   Total http packets processed: " << total << std::endl;
	}
}

/**
 * \brief Copy string and append \0 character.
 * NOTE: function removes any CR chars at the end of string.
 * \param [in] dst Destination buffer.
 * \param [in] size Size of destination buffer.
 * \param [in] begin Ptr to begin of source string.
 * \param [in] end Ptr to end of source string.
 */
void copy_str(char* dst, ssize_t size, const char* begin, const char* end)
{
	ssize_t len = end - begin;
	if (len >= size) {
		len = size - 1;
	}

	memcpy(dst, begin, len);

	if (len >= 1 && dst[len - 1] == '\n') {
		len--;
	}

	if (len >= 1 && dst[len - 1] == '\r') {
		len--;
	}

	dst[len] = 0;
}

/**
 * \brief Add delimiter and string at the end of destination buffer if is it empty add only string
 * and append \0 character. NOTE: function removes any CR chars at the end of string. \param [in]
 * dst Destination buffer. \param [in] size Size of destination buffer. \param [in] begin Ptr to
 * begin of source string. \param [in] end Ptr to end of source string. \param [in] delimiter
 * delimiter string
 */
void add_str(char* dst, ssize_t size, const char* begin, const char* end, const char* delimiter)
{
	ssize_t len_of_dst = strlen(dst);
	ssize_t len_of_delimiter = strlen(delimiter);
	ssize_t len = end - begin;
	if (len_of_dst > 0) {
		if (len_of_dst + len_of_delimiter + 1 >= size) {
			return;
		}
		if (len + len_of_dst + len_of_delimiter >= size) {
			len = size - len_of_dst - len_of_delimiter - 1;
		}
		dst = strcat(dst, delimiter);

		dst[len_of_dst + len_of_delimiter] = 0;
	} else if (len + len_of_dst > size) {
		len = size - len_of_dst - 1;
	}
	char src[len + 1];
	memcpy(src, begin, len);
	src[len] = 0;
	strcat(dst, src);
	if (len >= 1 && dst[len - 1] == '\n') {
		len--;
	}

	if (len >= 1 && dst[len - 1] == '\r') {
		len--;
	}
	if (len_of_dst > 0)
		dst[len + len_of_dst + len_of_delimiter] = 0;
	else
		dst[len] = 0;
}

bool HTTPPlugin::is_request(const char* data, int payload_len)
{
	char chars[5];

	if (payload_len < 4) {
		return false;
	}
	memcpy(chars, data, 4);
	chars[4] = 0;

	// 'valid_http_method' can quicky confirm valid http methods.
	// 'invalid_http_method' is slower but can check if it is http request even
	// if the method is invalid.
	return valid_http_method(chars) || invalid_http_method(data, payload_len);
}

bool HTTPPlugin::is_response(const char* data, int payload_len)
{
	char chars[5];

	if (payload_len < 4) {
		return false;
	}
	memcpy(chars, data, 4);
	chars[4] = 0;
	return !strcmp(chars, "HTTP");
}

#ifdef DEBUG_HTTP
static uint32_t s_requests = 0, s_responses = 0;
#endif /* DEBUG_HTTP */

/**
 * \brief Parse and store http request.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] rec Variable where http request will be stored.
 * \return True if request was parsed, false if error occured.
 */
bool HTTPPlugin::parse_http_request(const char* data, int payload_len, RecordExtHTTP* rec)
{
	char buffer[64];
	size_t remaining;
	const char *begin, *end, *keyval_delimiter;

	total++;

	DEBUG_MSG("---------- http parser #%u ----------\n", total);
	DEBUG_MSG("Parsing request number: %u\n", ++s_requests);
	DEBUG_MSG("Payload length: %u\n\n", payload_len);

	if (payload_len == 0) {
		DEBUG_MSG("Parser quits:\tpayload length = 0\n");
		return false;
	}

	/* Request line:
	 *
	 * METHOD URI VERSION
	 * |     |   |
	 * |     |   -------- end
	 * |     ------------ begin
	 * ----- ------------ data
	 */

	/* Find begin of URI. */
	begin = static_cast<const char*>(memchr(data, ' ', payload_len));
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tnot a http request header\n");
		return false;
	}

	/* Find end of URI. */
	if (check_payload_len(payload_len, (begin + 1) - data)) {
		DEBUG_MSG("Parser quits:\tpayload end\n");
		return false;
	}

	remaining = payload_len - ((begin + 1) - data);
	end = static_cast<const char*>(memchr(begin + 1, ' ', remaining));

	if (end == nullptr) {
		DEBUG_MSG("Parser quits:\trequest is fragmented\n");
		return false;
	}

	if (memcmp(end + 1, "HTTP", 4)) {
		DEBUG_MSG("Parser quits:\tnot a HTTP request\n");
		return false;
	}

	/* Copy and check HTTP method */
	copy_str(buffer, sizeof(buffer), data, begin);
	if (rec->req) {
		flow_flush = true;
		total--;
		DEBUG_MSG("Parser quits:\tflushing flow\n");
		return false;
	}
	strncpy(rec->method, buffer, sizeof(rec->method));
	rec->method[sizeof(rec->method) - 1] = 0;

	copy_str(rec->uri, sizeof(rec->uri), begin + 1, end);
	DEBUG_MSG("\tMethod: %s\n", rec->method);
	DEBUG_MSG("\tURI: %s\n", rec->uri);

	/* Find begin of next line after request line. */
	if (check_payload_len(payload_len, end - data)) {
		DEBUG_MSG("Parser quits:\tpayload end\n");
		return false;
	}
	remaining = payload_len - (end - data);
	begin = ipxp::strnstr(end, HTTP_LINE_DELIMITER, remaining);
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tNo line delim after request line\n");
		return false;
	}
	begin += 2;

	/* Header:
	 *
	 * REQ-FIELD: VALUE
	 * |        |      |
	 * |        |      ----- end
	 * |        ------------ keyval_delimiter
	 * --------------------- begin
	 */

	rec->host[0] = 0;
	rec->user_agent[0] = 0;
	rec->referer[0] = 0;
	/* Process headers. */
	while (begin - data < payload_len) {
		remaining = payload_len - (begin - data);
		end = ipxp::strnstr(begin, HTTP_LINE_DELIMITER, remaining);
		keyval_delimiter
			= static_cast<const char*>(memchr(begin, HTTP_KEYVAL_DELIMITER, remaining));

		if (end == nullptr) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		end += 1;
		int tmp = end - begin;
		if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
			break; /* Double LF found - end of header section. */
		} else if (keyval_delimiter == nullptr) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		/* Copy field name. */
		copy_str(buffer, sizeof(buffer), begin, keyval_delimiter);

		DEBUG_CODE(char debug_buffer[4096]);
		DEBUG_CODE(copy_str(debug_buffer, sizeof(debug_buffer), keyval_delimiter + 2, end));
		DEBUG_MSG("\t%s: %s\n", buffer, debug_buffer);

		/* Copy interesting field values. */
		if (!strcmp(buffer, "Host")) {
			copy_str(rec->host, sizeof(rec->host), keyval_delimiter + 2, end);
		} else if (!strcmp(buffer, "User-Agent")) {
			copy_str(rec->user_agent, sizeof(rec->user_agent), keyval_delimiter + 2, end);
		} else if (!strcmp(buffer, "Referer")) {
			copy_str(rec->referer, sizeof(rec->referer), keyval_delimiter + 2, end);
		}

		/* Go to next line. */
		begin = end + 1;
	}

	DEBUG_MSG("Parser quits:\tend of header section\n");
	rec->req = true;
	requests++;
	return true;
}

/**
 * \brief Parse and store http response.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] rec Variable where http response will be stored.
 * \return True if request was parsed, false if error occured.
 */
bool HTTPPlugin::parse_http_response(const char* data, int payload_len, RecordExtHTTP* rec)
{
	char buffer[64];
	const char *begin, *end, *keyval_delimiter, *cookie_name_end;
	size_t remaining;
	int code;

	total++;

	DEBUG_MSG("---------- http parser #%u ----------\n", total);
	DEBUG_MSG("Parsing response number: %u\n", ++s_responses);
	DEBUG_MSG("Payload length: %u\n\n", payload_len);

	if (payload_len == 0) {
		DEBUG_MSG("Parser quits:\tpayload length = 0\n");
		return false;
	}

	/* Check begin of response header. */
	if (memcmp(data, "HTTP", 4)) {
		DEBUG_MSG("Parser quits:\tpacket contains http response data\n");
		return false;
	}

	/* Response line:
	 *
	 * VERSION CODE REASON
	 * |      |    |
	 * |      |    --------- end
	 * |      -------------- begin
	 * --------------------- data
	 */

	/* Find begin of status code. */
	begin = static_cast<const char*>(memchr(data, ' ', payload_len));
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tnot a http response header\n");
		return false;
	}

	/* Find end of status code. */
	if (check_payload_len(payload_len, (begin + 1) - data)) {
		DEBUG_MSG("Parser quits:\tpayload end\n");
		return false;
	}
	remaining = payload_len - ((begin + 1) - data);
	end = static_cast<const char*>(memchr(begin + 1, ' ', remaining));
	if (end == nullptr) {
		DEBUG_MSG("Parser quits:\tresponse is fragmented\n");
		return false;
	}

	/* Copy and check HTTP response code. */
	copy_str(buffer, sizeof(buffer), begin + 1, end);
	code = atoi(buffer);
	if (code <= 0) {
		DEBUG_MSG("Parser quits:\twrong response code: %d\n", code);
		return false;
	}

	DEBUG_MSG("\tCode: %d\n", code);
	if (rec->resp) {
		flow_flush = true;
		total--;
		DEBUG_MSG("Parser quits:\tflushing flow\n");
		return false;
	}
	rec->code = code;

	/* Find begin of next line after request line. */
	if (check_payload_len(payload_len, end - data)) {
		DEBUG_MSG("Parser quits:\tpayload end\n");
		return false;
	}
	remaining = payload_len - (end - data);
	begin = ipxp::strnstr(end, HTTP_LINE_DELIMITER, remaining);
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tNo line delim after request line\n");
		return false;
	}
	begin += 2;

	/* Header:
	 *
	 * REQ-FIELD: VALUE
	 * |        |      |
	 * |        |      ----- end
	 * |        ------------ keyval_delimiter
	 * --------------------- begin
	 */

	rec->content_type[0] = 0;
	rec->server[0] = 0;
	rec->set_cookie[0] = 0;

	/* Process headers. */
	while (begin - data < payload_len) {
		remaining = payload_len - (begin - data);
		end = ipxp::strnstr(begin, HTTP_LINE_DELIMITER, remaining);
		keyval_delimiter
			= static_cast<const char*>(memchr(begin, HTTP_KEYVAL_DELIMITER, remaining));

		if (end == nullptr) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		end += 1;
		int tmp = end - begin;
		if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
			break; /* Double LF found - end of header section. */
		} else if (keyval_delimiter == nullptr) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		/* Copy field name. */
		copy_str(buffer, sizeof(buffer), begin, keyval_delimiter);

		DEBUG_CODE(char debug_buffer[4096]);
		DEBUG_CODE(copy_str(debug_buffer, sizeof(debug_buffer), keyval_delimiter + 2, end));
		DEBUG_MSG("\t%s: %s\n", buffer, debug_buffer);

		/* Copy interesting field values. */
		if (!strcmp(buffer, "Content-Type")) {
			copy_str(rec->content_type, sizeof(rec->content_type), keyval_delimiter + 2, end);
		} else if (!strcmp(buffer, "Server")) {
			copy_str(rec->server, sizeof(rec->server), keyval_delimiter + 2, end);
		} else if (!strcmp(buffer, "Set-Cookie")) {
			cookie_name_end
				= ipxp::strnstr(begin, HTTP_SETCOOKIE_NAME_DELIMITER, size_t(end - begin));
			if (cookie_name_end == nullptr) {
				break;
			}
			add_str(
				rec->set_cookie,
				sizeof(rec->set_cookie),
				keyval_delimiter + 2,
				cookie_name_end,
				STRING_DELIMITER);
		}

		/* Go to next line. */
		begin = end + 1;
	}

	DEBUG_MSG("Parser quits:\tend of header section\n");
	rec->resp = true;
	responses++;
	return true;
}

/**
 * \brief Check http method.
 * \param [in] method C string with http method.
 * \return True if http method is valid.
 */
bool HTTPPlugin::valid_http_method(const char* method) const
{
	return (
		!strcmp(method, "GET ") || !strcmp(method, "POST") || !strcmp(method, "PUT ")
		|| !strcmp(method, "HEAD") || !strcmp(method, "DELE") || !strcmp(method, "TRAC")
		|| !strcmp(method, "OPTI") || !strcmp(method, "CONN") || !strcmp(method, "PATC"));
}

/**
 * @brief Check if the payload is http request even with invalid method.
 *
 * @param [in] payload Packet payload data.
 * @param payload_len Length packet payload.
 * @return True if the packet is http request.
 */
bool HTTPPlugin::invalid_http_method(const char* data, int payload_len) const
{
	// arbitrary value, if the method is longer it propably isnt http request
	// so don't look further
	const int MAX_METHOD_LENGTH = 32;

	// METHOD URI HTTP/VERSION
	// |     |   |
	// |     |   +---- uri_end
	// |     +---- method_end
	// +---- data

	// check if there is space in the first HTTP_MAX_METHOD_LENGTH chars
	int len = std::min(payload_len, MAX_METHOD_LENGTH);
	auto method_end = static_cast<const char*>(memchr(data, ' ', len));
	if (method_end == nullptr)
		return false;

	payload_len -= method_end - data - 1;
	if (payload_len <= 0)
		return false;

	auto uri_end = static_cast<const char*>(memchr(method_end + 1, ' ', payload_len));
	if (uri_end == nullptr)
		return false;

	payload_len -= uri_end - method_end;
	if (payload_len <= 4)
		return false;

	return memcmp(uri_end + 1, "HTTP", 4) == 0;
}

/**
 * \brief Add new extension http request header into flow record.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] flow Flow record where to store created extension header.
 */
void HTTPPlugin::add_ext_http_request(const char* data, int payload_len, Flow& flow)
{
	if (recPrealloc == nullptr) {
		recPrealloc = new RecordExtHTTP();
	}

	if (parse_http_request(data, payload_len, recPrealloc)) {
		flow.add_extension(recPrealloc);
		recPrealloc = nullptr;
	}
}

/**
 * \brief Add new extension http response header into flow record.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] flow Flow record where to store created extension header.
 */
void HTTPPlugin::add_ext_http_response(const char* data, int payload_len, Flow& flow)
{
	if (recPrealloc == nullptr) {
		recPrealloc = new RecordExtHTTP();
	}

	if (parse_http_response(data, payload_len, recPrealloc)) {
		flow.add_extension(recPrealloc);
		recPrealloc = nullptr;
	}
}

} // namespace ipxp
