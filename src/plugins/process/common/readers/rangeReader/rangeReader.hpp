#pragma once

namespace ipxp
{
    
class RangeReader {
public:

    constexpr bool parsedSuccessfully() const noexcept 
    {
        return m_state == State::SUCCESS;
    }
      
protected:
    constexpr void setSuccess() noexcept 
    {
        m_state = State::SUCCESS;
    }
private:
    enum class State {
        SUCCESS,
        FAILURE
    };  

    State m_state{State::FAILURE};
};



} // namespace ipxp
