#pragma once

#include <span>
#include <views>
#include <optional>
#include <common/rangeReader/rangeReader.hpp>
#include <common/rangeReader/generator.hpp>

namespace ipxp
{

template<typename LengthType>
class PrefixedLengthStringReader;


template<typename LengthType>
struct PrefixedLengthStringReaderFactory {
    PrefixedLengthStringReader* self;

    auto operator()(std::span<const std::byte> extension) const {
        return Generator::generate([extension, self = self]() mutable -> std::optional<std::string_view> {
            if (extension.empty()) {
                self->setSuccess();
                return std::nullopt;
            }

            if (extension.size() < sizeof(LengthType)) {
                self->setFailed();
                return std::nullopt;
            }

            const LengthType length = ntohs(*reinterpret_cast<const uint16_t*>(extension.data()));
            if (extension.size() < length + sizeof(length)) {
                self->setFailed();
                return std::nullopt;
            }

            const auto label = reinterpret_cast<const char*>(extension.data() + sizeof(length));
            extension = extension.subspan(length + sizeof(length));

            return std::string_view(label, length);
        }) | std::views::take_while([](const std::optional<std::string_view>& v) {
            return v.has_value();
        }) | std::views::transform([](const std::optional<std::string_view>& v) {
            return *v;
        });
    }
};

template<typename LengthType>
class PrefixedLengthStringReader : public RangeReader<PrefixedLengthStringReaderFactory<LengthType>> {
public:
    PrefixedLengthStringReader(std::span<const std::byte> extension)
        : RangeReader(extension, PrefixedLengthStringReaderFactory{this}) {}
};

} // namespace ipxp
