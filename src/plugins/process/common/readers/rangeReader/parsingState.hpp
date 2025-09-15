#pragma once

namespace ipxp
{
    
struct ParsingState {
    /*constexpr void setSuccess() noexcept 
    {
        m_state = State::SUCCESS;
    }*/
    enum class State {
        SUCCESS,
        FAILURE
    };    
    State state{State::FAILURE};
};    

} // namespace ipxp
