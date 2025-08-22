#pragma once

namespace ipxp
{
    
template<typename Function>
struct FunctionTraits;

template<typename R, typename... Args>
struct FunctionTraits<R(*)(Args...)> {
    using ArgumentTypes = std::tuple<Args...>;

    /*using ReturnType = decltype(
        std::declval<R(*)(Args...)>()(std::declval<Args>()...)
    );*/
};

template<typename Func, typename Tuple>
struct ReturnType;

template<typename Func, typename... Args>
struct ReturnType<Func, std::tuple<Args...>> {
    using Type = std::invoke_result_t<Func, Args...>;
};



} // namespace ipxp
