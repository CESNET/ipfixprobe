#pragma once

#include <string_view>
#include "../../dns/src/dnsRecord.hpp"

namespace ipxp
{
    
struct DNSSDRecord : DNSRecord {
    std::string_view requestName;

    std::string toString() const noexcept;
};


} // namespace ipxp
