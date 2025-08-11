#pragma once

#include <variant>

#include "dnsQueryType.hpp"
#include "../dnsRecordPayloadTypes/dnsARecord.hpp"
#include "../dnsRecordPayloadTypes/dnsAAAARecord.hpp"
#include "../dnsRecordPayloadTypes/dnsDSRecord.hpp"
#include "../dnsRecordPayloadTypes/dnsHINFORecord.hpp"
#include "../dnsRecordPayloadTypes/dnsSDNRecord.hpp"
#include "../dnsRecordPayloadTypes/dnsKEYRecord.hpp"
#include "../dnsRecordPayloadTypes/dnsMINFORecord.hpp"
#include "../dnsRecordPayloadTypes/dnsMXRecord.hpp"
#include "../dnsRecordPayloadTypes/dnsPTRRecord.hpp"
#include "../dnsRecordPayloadTypes/dnsRRSIGRecord.hpp"
#include "../dnsRecordPayloadTypes/dnsSOARecord.hpp"
#include "../dnsRecordPayloadTypes/dnsTXTRecord.hpp"

namespace ipxp
{

using DNSRecordPayloadType = std::variant<
    dnsARecord,
    dnsAAAARecord,
    dnsDSRecord,
    dnsHINFORecord,
    dnsSDNRecord,
    dnsKEYRecord,
    dnsMINFORecord,
    dnsMXRecord,
    dnsPTRRecord,
    dnsRRSIGRecord,
    dnsSOARecord,
    dnsTXTRecord
>;
    
class DNSRecordPayload
{
public:
    DNSRecordPayload(
        std::span<const std::byte> data, 
        std::span<const std::byte> fullDNSPayload,
        DNSQueryType type) noexcept
    : m_data(data), m_fullDNSPayload(fullDNSPayload), m_type(type)
    {}

    DNSRecordPayload() noexcept {}

    std::optional<DNSRecordPayloadType> getUnderlyingType() const noexcept
    {
        switch (m_type) {
        case DNSQueryType::A:
            return dnsARecord::createFrom(m_data);
        case DNSQueryType::AAAA:
            return dnsAAAARecord::createFrom(m_data);
        case DNSQueryType::NS: [[fallthrough]];
        case DNSQueryType::CNAME: [[fallthrough]];
        case DNSQueryType::PTR:
            return dnsPTRRecord::createFrom(m_data, m_fullDNSPayload);
        case DNSQueryType::SOA:
            return dnsSOARecord::createFrom(m_data, m_fullDNSPayload);
        case DNSQueryType::MX:
            return dnsMXRecord::createFrom(m_data, m_fullDNSPayload);
        case DNSQueryType::TXT:
            return dnsTXTRecord::createFrom(m_data, m_fullDNSPayload);
        case DNSQueryType::ISDN:
            return dnsISDNRecord::createFrom(m_data, m_fullDNSPayload);
        case DNSQueryType::HINFO:
            return dnsHINFORecord::createFrom(m_data, m_fullDNSPayload);
        case DNSQueryType::MINFO:
            return dnsMINFORecord::createFrom(m_data, m_fullDNSPayload);
        case DNSQueryType::SRV:
            return dnsSRVRecord::createFrom(m_data, m_fullDNSPayload);
        case DNSQueryType::RRSIG:
            return dnsRRSIGRecord::createFrom(m_data);
        case DNSQueryType::DNSKEY:
            return dnsKEYRecord::createFrom(m_data);
        case DNSQueryType::DS:
            return dnsDSRecord::createFrom(m_data);
        default:
            return std::nullopt;
        }
    }

    constexpr std::span<const std::byte> getPayload() const noexcept
    {
        return m_data;
    }

private:
    std::span<const std::byte> m_data;
    std::span<const std::byte> m_fullDNSPayload;
    DNSQueryType m_type;
};

} // namespace ipxp
