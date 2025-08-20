#pragma once

namespace ipxp
{
    
template<typename Function>
struct FunctionTraits;

template<typename R, typename... Args>
struct FunctionTraits<R(*)(Args...)> {
    using ReturnType = R;
};

} // namespace ipxp
