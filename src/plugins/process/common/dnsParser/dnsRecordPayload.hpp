/**
 * @file
 * @brief Provides DNS record payload structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnsQueryType.hpp"
#include "dnsRecordPayloadTypes/dnsAAAARecord.hpp"
#include "dnsRecordPayloadTypes/dnsARecord.hpp"
#include "dnsRecordPayloadTypes/dnsDSRecord.hpp"
#include "dnsRecordPayloadTypes/dnsHINFORecord.hpp"
#include "dnsRecordPayloadTypes/dnsISDNRecord.hpp"
#include "dnsRecordPayloadTypes/dnsKEYRecord.hpp"
#include "dnsRecordPayloadTypes/dnsMINFORecord.hpp"
#include "dnsRecordPayloadTypes/dnsMXRecord.hpp"
#include "dnsRecordPayloadTypes/dnsPTRRecord.hpp"
#include "dnsRecordPayloadTypes/dnsRRSIGRecord.hpp"
#include "dnsRecordPayloadTypes/dnsSOARecord.hpp"
#include "dnsRecordPayloadTypes/dnsSRVRecord.hpp"
#include "dnsRecordPayloadTypes/dnsTXTRecord.hpp"

#include <variant>

namespace ipxp {

using DNSRecordPayloadType = std::variant<
	DNSARecord,
	DNSAAAARecord,
	DNSDSRecord,
	DNSHINFORecord,
	DNSISDNRecord,
	DNSKEYRecord,
	DNSMINFORecord,
	DNSMXRecord,
	DNSPTRRecord,
	DNSRRSIGRecord,
	DNSSOARecord,
	DNSSRVRecord,
	DNSTXTRecord>;

/**
 * @class DNSRecordPayload
 * @brief Represents the payload of a DNS record, capable of parsing various DNS record types.
 *
 * This class encapsulates the raw payload data of a DNS record and provides functionality
 * to interpret it according to the specified DNS query type. It supports multiple DNS record
 * types, each represented by a distinct structure.
 */
class DNSRecordPayload {
public:
	DNSRecordPayload(
		std::span<const std::byte> data,
		std::span<const std::byte> fullDNSPayload,
		DNSQueryType type) noexcept
		: m_data(data)
		, m_fullDNSPayload(fullDNSPayload)
		, m_type(type)
	{
	}

	DNSRecordPayload() noexcept {}

	std::optional<DNSRecordPayloadType> getUnderlyingType() const noexcept
	{
		switch (m_type) {
		case DNSQueryType::A:
			return DNSARecord::createFrom(m_data);
		case DNSQueryType::AAAA:
			return DNSAAAARecord::createFrom(m_data);
		case DNSQueryType::NS:
			[[fallthrough]];
		case DNSQueryType::CNAME:
			[[fallthrough]];
		case DNSQueryType::PTR:
			return DNSPTRRecord::createFrom(m_data, m_fullDNSPayload);
		case DNSQueryType::SOA:
			return DNSSOARecord::createFrom(m_data, m_fullDNSPayload);
		case DNSQueryType::MX:
			return DNSMXRecord::createFrom(m_data, m_fullDNSPayload);
		case DNSQueryType::TXT:
			return DNSTXTRecord::createFrom(m_data, m_fullDNSPayload);
		case DNSQueryType::ISDN:
			return DNSISDNRecord::createFrom(m_data, m_fullDNSPayload);
		case DNSQueryType::HINFO:
			return DNSHINFORecord::createFrom(m_data, m_fullDNSPayload);
		case DNSQueryType::MINFO:
			return DNSMINFORecord::createFrom(m_data, m_fullDNSPayload);
		case DNSQueryType::SRV:
			return DNSSRVRecord::createFrom(m_data, m_fullDNSPayload);
		case DNSQueryType::RRSIG:
			return DNSRRSIGRecord::createFrom(m_data);
		case DNSQueryType::DNSKEY:
			return DNSKEYRecord::createFrom(m_data);
		case DNSQueryType::DS:
			return DNSDSRecord::createFrom(m_data);
		default:
			return std::nullopt;
		}
	}

	constexpr std::span<const std::byte> getSpan() const noexcept { return m_data; }

private:
	std::span<const std::byte> m_data;
	std::span<const std::byte> m_fullDNSPayload;
	DNSQueryType m_type;
};

} // namespace ipxp
