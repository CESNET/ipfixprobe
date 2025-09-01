
#include <span>
#include <ranges>
#include <optional>
#include <readers/rangeReader/rangeReader.hpp>
#include <readers/rangeReader/generator.hpp>

#include "../../../quic/src/quicVariableInt.hpp"

namespace ipxp
{

struct UserAgent {
    uint64_t id;
    std::string_view value;
};

struct UserAgentReader : public RangeReader {

    auto getRange(std::span<const std::byte> userAgentExtension) noexcept
    {
        return Generator::generate([this, userAgentExtension]() mutable 
        -> std::optional<UserAgent> {
            if (userAgentExtension.empty()) {
                setSuccess();
                return std::nullopt;
            }
            const std::optional<VariableLengthInt> id
                = readQUICVariableLengthInt(userAgentExtension);
            if (!id.has_value()) {
                return std::nullopt;
            }

            const std::size_t lengthOffset = id->length;
            const std::optional<VariableLengthInt> userAgentLength
                = readQUICVariableLengthInt(userAgentExtension.subspan(lengthOffset));
            if (!userAgentLength.has_value()) {
                return std::nullopt;
            }
            if (id->length + userAgentLength->length + userAgentLength->value 
                    > userAgentExtension.size()) {
                return std::nullopt;
            }

            const std::size_t userAgentOffset = lengthOffset + userAgentLength->length;
            const auto userAgent = reinterpret_cast<const char*>(
                userAgentExtension.data() + userAgentOffset);

            userAgentExtension = userAgentExtension.subspan(userAgentOffset + userAgentLength->length);

            return UserAgent{id->value, {userAgent, userAgentLength->value}};
        }) | std::views::take_while([](const std::optional<UserAgent>& v) {
            return v.has_value();
        }) | std::views::transform([](const std::optional<UserAgent>& v) {
            return *v;
        });
    }
};

/*
class TLSUserAgentReader : public RangeReader<UserAgentReaderFactory> {
public:
    TLSUserAgentReader(std::span<const std::byte> userAgentExtension)
        : RangeReader(userAgentExtension, UserAgentReaderFactory{this}) {}
};*/

} // namespace ipxp