#pragma once

namespace ipxp
{
    
template<typename Derived>
class RangeReader {
    enum class ParsingState {
        SUCCESS,
        FAILURE
    };

public:
    RangeReader() noexcept
        //: m_callback(callback->init())
    {
    }

    auto getCallback() const noexcept 
    {
        return static_cast<const Derived*>(this)->m_callback;
    }

    constexpr auto begin() const noexcept 
    {
        return getCallback().begin();
    }

    constexpr auto end() const noexcept 
    {
        return getCallback().end();
    }

    /*constexpr auto begin() noexcept 
    {
        return m_callback.begin();
    }

    constexpr auto end() noexcept 
    {
        return m_callback.end();
    }*/

    constexpr bool parsedSuccessfully() const noexcept 
    {
        return m_state == ParsingState::SUCCESS;
    }

protected:
    

    constexpr void setSuccess() noexcept {
        m_state = ParsingState::SUCCESS;
    }

    //decltype(std::declval<Derived>().init()) m_callback;

private:
    ParsingState m_state{ParsingState::FAILURE};
};



} // namespace ipxp
