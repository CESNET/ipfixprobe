
#include <span>
#include <views>
#include <optional>
#include <common/rangeReader/rangeReader.hpp>
#include <common/rangeReader/generator.hpp>

#include "../../quic/quicVariableInt.hpp"

namespace ipxp
{

struct UserAgent {
    uint64_t id;
    std::string_view value;
};

class TLSUserAgentReader;

struct UserAgentReaderFactory {
    TLSUserAgentReader* self;

    auto operator()(std::span<const std::byte> userAgentExtension) const {
        return Generator::generate([userAgentExtension, self = self](int) mutable -> std::optional<UserAgent> {
            if (userAgentExtension.empty()) {
                self->setSuccess();
                return std::nullopt;
            }
            const std::optional<VariableLengthInt> id
                = readQUICVariableLengthInt(userAgentExtension);
            if (!id.has_value()) {
                self->setFailed();
                return std::nullopt;
            }

            const std::size_t lengthOffset = id->length;
            const std::optional<VariableLengthInt> userAgentLength
                = readQUICVariableLengthInt(userAgentExtension.subspan(lengthOffset));
            if (!userAgentLength.has_value()) {
                self->setFailed();
                return std::nullopt;
            }
            if (id->length + userAgentLength->length + userAgentLength 
                    > userAgentExtension.size()) {
                self->setFailed();
                return std::nullopt;
            }

            const std::size_t userAgentOffset = lengthOffset + userAgentLength->length;
            const auto userAgent = reinterpret_cast<const char*>(
                userAgentExtension.data() + userAgentOffset);

            userAgentExtension = userAgentExtension.subspan(userAgentOffset + userAgentLength->length);

            return {id->value, {userAgent, userAgentLength->value}};
        }) | std::views::take_while([](const std::optional<UserAgent>& v) {
            return v.has_value();
        }) | std::views::transform([](const std::optional<UserAgent>& v) {
            return *v;
        });
    }
};

class TLSUserAgentReader : public RangeReader<UserAgentReaderFactory> {
public:
    TLSUserAgentReader(std::span<const std::byte> userAgentExtension)
        : RangeReader(userAgentExtension, UserAgentReaderFactory{this}) {}
};

} // namespace ipxp