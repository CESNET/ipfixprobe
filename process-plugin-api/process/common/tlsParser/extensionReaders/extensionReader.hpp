
#include <span>
#include <views>
#include <optional>
#include <rangeReader/rangeReader.hpp>
#include <rangeReader/generator.hpp>

#include "../tlsExtensionType.hpp"

namespace ipxp
{

struct Extension {
    ExtensionType type;
    std::span<const std::byte> payload;
};

class ExtensionReader;

struct ExtensionReaderFactory {
    ExtensionReader* self;

    auto operator()(std::span<const std::byte> payload) const {
        return Generator::generate([payload, self = self](int) mutable -> std::optional<Extension> {
            if (payload.empty()) {
                self->setSuccess();
                return std::nullopt;
            }
            if (payload.size() < sizeof(uint16_t)) {
                self->setFailed();
                return std::nullopt;
            }

            const uint16_t length 
                = ntohs(*reinterpret_cast<const uint16_t*>(extension.data()));
            if (length > extension.size() || length < sizeof(uint16_t)) {
                self->setFailed();
                return std::nullopt;
            }

            const auto type = static_cast<ExtensionType>(
                ntohs(*reinterpret_cast<const uint16_t*>(
                    extension.data() + sizeof(length))));

            const auto extensionBegin 
                = payload.data() + sizeof(type) + sizeof(length);
            
            payload 
                = payload.subspan(sizeof(type) + sizeof(length) + length);

            return Extension{type, {extensionBegin, length}};
        }) | std::views::take_while([](const std::optional<Extension>& v) {
            return v.has_value();
        }) | std::views::transform([](const std::optional<Extension>& v) {
            return *v;
        });
    }
};

class ExtensionReader : public RangeReader<ExtensionReaderFactory> {
public:
    ExtensionReader(std::span<const std::byte> payload)
        : RangeReader(payload, ExtensionReaderFactory{this}) {}
};

} // namespace ipxp