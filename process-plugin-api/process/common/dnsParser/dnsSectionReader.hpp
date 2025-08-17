#pragma once

#include <span>
#include <views>
#include <optional>
#include <readers/rangeReader/rangeReader.hpp>
#include <readers/rangeReader/generator.hpp>

#include "dnsRecord.hpp"

namespace ipxp
{

class DNSSectionReader;

struct DNSSectionReaderFactory {
    DNSSectionReader* self;
    std::size_t itemCount;
    std::span<const std::byte> fullDNSPayload;

    auto operator()(std::span<const std::byte> section) const {
        return Generator::generate([section, self = self, itemCount, fullDNSPayload]() mutable
        -> std::optional<DNSRecord>& {
            static auto res = std::make_optional<DNSRecord>();
            if (itemCount == 0) {
                self->setSuccess();
                return std::nullopt;
            }
            itemCount--;

            std::optional<DNSName> name = DNSName::createFrom(
                section, fullDNSPayload);
            if (!name.has_value()) {
                return std::nullopt;
            }
            if (name->length() + 3 * sizeof(uint16_t) + sizeof(uint32_t) > section.size()) {
                return std::nullopt;
            }
            res->name = std::move(*name);

            res->type = ntohs(*reinterpret_cast<const uint16_t*>(
                section.data() + name->length()));
            
            res->recordClass = ntohs(
                *reinterpret_cast<const uint16_t*>(section.data() + name->length() + sizeof(type)));

            res->timeToLive = ntohl(*reinterpret_cast<const uint32_t*>(
                section.data() + name->length() + 2 * sizeof(uint16_t)));

            res->rawDataLength = ntohs(*reinterpret_cast<const uint16_t*>(
                section.data() + name->length() + 2 * sizeof(uint16_t) + sizeof(ttl)));
            if (name->length() + 3 * sizeof(uint16_t) + sizeof(uint32_t) + rawDataLength
                > section.size()) {
                return std::nullopt;
            }

            std::span<const std::byte> rawData = section.subspan(
                name->length() + 3 * sizeof(uint16_t) + sizeof(uint32_t), rawDataLength);
            res->dnsPayload(rawData, fullDNSPayload, type);

            section = section.subspan(
                name->length() + 3 * sizeof(uint16_t) + sizeof(uint32_t) + rawDataLength);

            return res;
        }) | std::views::take_while([](const std::optional<DNSRecord>& v) {
            return v.has_value();
        }) | std::views::transform([](const std::optional<DNSRecord>& v) {
            return *v;
        });
    }
};

class DNSSectionReader : public RangeReader<DNSSectionReaderFactory> {
public:
    DNSSectionReader(std::span<const std::byte> section, 
        std::span<const std::byte> fullDNSPayload, const std::size_t itemCount)
        : RangeReader(section, DNSSectionReaderFactory{this, itemCount, fullDNSPayload.data()}) {}
};

} // namespace ipxp
