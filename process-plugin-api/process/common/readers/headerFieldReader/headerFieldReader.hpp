// Common for RTSP, SIP, SMTP, HTTP
#pragma once

#include <span>
#include <string_view>
#include <optional>
#include <ranges>

#include <rangeReader/rangeReader.hpp>
#include <rangeReader/generator.hpp>

namespace ipxp
{
    
struct HeaderField {
    std::string_view key;
    std::string_view value;
};

class HeaderFieldReader;

struct HeaderFieldReaderFactory {
    HeaderFieldReader* self;

    auto operator()(std::span<const std::byte> payload) const {
        return Generator::generate([payload, self = self]() mutable -> std::optional<HeaderField> {
            auto extensionEnd = std::ranges::find(payload, std::byte{'\n'});
            if (extensionEnd == payload.end()) {
                return std::nullopt;
            }

            if (std::distance(payload.begin(), extensionEnd) < 2) {
                self->setSuccess();
                return std::nullopt;
            }

            auto delimiterIt 
                = std::ranges::find(payload, std::byte{':'});
            if (std::distance(delimiterIt, payload.end()) < 2) {
                return std::nullopt;
            }

            std::string_view key 
                = {reinterpret_cast<const char*>(
                    payload.data()), delimiterIt - payload.data()};

            std::string_view value
                = {reinterpret_cast<const char*>(
                    delimiterIt + 2), extensionEnd - delimiterIt - 2};
            
            payload 
                = payload.subspan(extensionEnd - payload.data());

            return HeaderField{key, value};
        }) | std::views::take_while([](const std::optional<HeaderField>& v) {
            return v.has_value();
        }) | std::views::transform([](const std::optional<HeaderField>& v) {
            return *v;
        });
    }
};

class HeaderFieldReader : public RangeReader<HeaderFieldReaderFactory> {
public:
    HeaderFieldReader(std::span<const std::byte> payload)
        : RangeReader(payload, HeaderFieldReaderFactory{this}) {}
};


} // namespace ipxp
