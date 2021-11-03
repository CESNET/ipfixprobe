/**
 * \file flexprobe-data-processing.cpp
 * \brief Data processing for Flexprobe -- HW accelerated network probe
 * \author Roman Vrana <ivrana@fit.vutbr.cz>
 * \date 2021
 */

#include "flexprobe-data-processing.h"

namespace ipxp {

int FrameSignature::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("flexprobe-data", [](){return new FlexprobeDataProcessing();});
   register_plugin(&rec);
   FrameSignature::REGISTERED_ID = register_extension();
}

}
