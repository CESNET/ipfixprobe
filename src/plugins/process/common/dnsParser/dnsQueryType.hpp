/**
 * @file
 * @brief Provides DNS query type enumeration.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @brief DNS query type
 */
enum DNSQueryType : uint8_t {
	A = 1, /**< IPv4 address */
	NS = 2, /**< Name server */
	CNAME = 5, /**< Canonical name */
	SOA = 6, /**< Start of authority */
	PTR = 12, /**< Pointer */
	HINFO = 13, /**< Host information */
	MINFO = 14, /**< Mailbox information */
	MX = 15, /**< Mail exchange */
	TXT = 16, /**< Text */
	ISDN = 20, /**< ISDN */
	AAAA = 28, /**< IPv6 address */
	SRV = 33, /**< Service */
	DNAME = 39, /**< Delegation name */
	OPT = 41, /**< Options */
	DS = 43, /**< Delegation signer */
	RRSIG = 46, /**< Resource record signature */
	DNSKEY = 48, /**< DNS key */
};

} // namespace ipxp
