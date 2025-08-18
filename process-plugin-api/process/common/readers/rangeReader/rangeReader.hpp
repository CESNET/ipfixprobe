#pragma once

#include "parsingState.hpp"

namespace ipxp
{
    
template<typename CallbackType>
class RangeReader {
public:
    RangeReader(CallbackType&& callback) noexcept
        : m_callback(std::move(callback))
    {
    }

    constexpr auto begin() const noexcept 
    {
        return m_callback.begin();
    }

    constexpr auto end() const noexcept 
    {
        return m_callback.end();
    }

    constexpr auto begin() noexcept 
    {
        return m_callback.begin();
    }

    constexpr auto end() noexcept 
    {
        return m_callback.end();
    }

    constexpr bool parsedSuccessfully() const noexcept 
    {
        return m_state.state == ParsingState::State::SUCCESS;
    }

protected:
    ParsingState m_state;
private:
    CallbackType m_callback;
};



} // namespace ipxp
