#pragma once

#include <cstdint>

namespace ipxp
{
    
template<typename Type>
struct VariableLengthType {
    Type value;
    uint16_t length;
};

} // namespace ipxp
