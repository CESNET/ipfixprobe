#pragma once

#include <span>
#include <views>
#include <optional>
#include <rangeReader/rangeReader.hpp>
#include <rangeReader/generator.hpp>


namespace ipxp
{

struct Extension {
    std::string_view key;
    std::string_view value;
};

class RTSPExtensionReader;

struct RTSPExtensionReaderFactory {
    RTSPExtensionReader* self;

    auto operator()(std::span<const std::byte> payload) const {
        return Generator::generate([payload, self = self]() mutable -> std::optional<Extension> {
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

            return Extension{key, value};
        }) | std::views::take_while([](const std::optional<Extension>& v) {
            return v.has_value();
        }) | std::views::transform([](const std::optional<Extension>& v) {
            return *v;
        });
    }
};

class RTSPExtensionReader : public RangeReader<RTSPExtensionReaderFactory> {
public:
    RTSPExtensionReader(std::span<const std::byte> payload)
        : RangeReader(payload, RTSPExtensionReaderFactory{this}) {}
};

} // namespace ipxp