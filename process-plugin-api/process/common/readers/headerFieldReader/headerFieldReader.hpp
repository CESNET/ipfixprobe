// Common for RTSP, SIP, SMTP, HTTP
#pragma once

#include <span>
#include <string_view>
#include <optional>
#include <ranges>

#include <readers/rangeReader/rangeReader.hpp>
#include <readers/rangeReader/generator.hpp>

namespace ipxp
{
    
struct HeaderField {
    std::string_view key;
    std::string_view value;
};

struct HeaderFieldReader : public RangeReader {

    auto getRange(std::string_view payload) noexcept 
    {
        return Generator::generate([this, payload]() mutable 
        -> std::optional<HeaderField> {
            const std::size_t extensionEnd = payload.find("\r\n");  
            //auto extensionEnd = std::ranges::find(payload, std::byte{'\n'});
            if (extensionEnd == std::string_view::npos) {
                return std::nullopt;
            }

            if (extensionEnd < 2) {
                setSuccess();
                return std::nullopt;
            }

            auto delimiterPos = payload.find(':');
            if (delimiterPos < 2) {
                return std::nullopt;
            }

            std::string_view key = payload.substr(0, delimiterPos);

            std::string_view value 
                = payload.substr(delimiterPos + 2, extensionEnd - delimiterPos - 2);

            payload 
                = payload.substr(extensionEnd);

            return HeaderField{key, value};
        }) | std::views::take_while([](const std::optional<HeaderField>& v) {
            return v.has_value();
        }) | std::views::transform([](const std::optional<HeaderField>& v) {
            return *v;
        });
    }
};

/*

class HeaderFieldReader : public RangeReader<HeaderFieldReaderFactory> {
public:
    HeaderFieldReader(std::span<const std::byte> payload)
        : RangeReader(payload, HeaderFieldReaderFactory{this}) {}
};*/


} // namespace ipxp
