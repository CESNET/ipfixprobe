
#include <span>
#include <ranges>
#include <optional>
#include <readers/rangeReader/rangeReader.hpp>
#include <readers/rangeReader/generator.hpp>

#include "../tlsExtension.hpp"

namespace ipxp
{



class ExtensionReader;

struct ExtensionReaderFactory {

    static auto operator()(
        std::span<const std::byte> payload
    ) noexcept {
        return Generator::generate([payload, self = self](int) mutable -> std::optional<Extension> {
            if (payload.empty()) {
                self->setSuccess();
                return std::nullopt;
            }
            if (payload.size() < sizeof(uint16_t)) {
                return std::nullopt;
            }

            const uint16_t length 
                = ntohs(*reinterpret_cast<const uint16_t*>(extension.data()));
            if (length > extension.size() || length < sizeof(uint16_t)) {
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