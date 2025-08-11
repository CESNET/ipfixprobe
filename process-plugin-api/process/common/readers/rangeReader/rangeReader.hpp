#pragma once

namespace ipxp
{
    
template<typename parsingCallbackFactory>
class RangeReader {
    enum class ParsingState {
        SUCCESS,
        FAILURE
    };

public:
    RangeReader(std::span<const std::byte> data, 
        parsingCallbackFactory& callbackFactory) noexcept
        : m_callback(callbackFactory(data))
    {
    }

    constexpr auto begin() const noexcept {
        return m_reader.begin();
    }

    constexpr auto end() const noexcept {
        return m_reader.end();
    }

    constexpr auto begin() noexcept {
        return m_reader.begin();
    }

    constexpr auto end() noexcept {
        return m_reader.end();
    }

    constexpr bool parsedSuccessfully() const noexcept {
        return m_state == ParsingState::SUCCESS;
    }

protected:

    constexpr void setSuccess() noexcept {
        m_state = ParsingState::SUCCESS;
    }

private:
    ParsingState m_state{ParsingState::FAILURE};
    decltype(makeReader(std::span<const std::byte>{})) m_reader;
};



} // namespace ipxp
