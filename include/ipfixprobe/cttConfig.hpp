#pragma once

#include <string>

namespace ipxp {

struct CttConfig {
    std::string nfb_device;
    unsigned dma_channel;
};

} // namespace ipxp