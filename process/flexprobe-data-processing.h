/**
 * \file flexprobe-data-processing.h
 * \brief Data processing for Flexprobe -- HW accelerated network probe
 * \author Roman Vrana <ivrana@fit.vutbr.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */
#ifndef IPFIXPROBE_FLEXPROBE_DATA_PROCESSING_H
#define IPFIXPROBE_FLEXPROBE_DATA_PROCESSING_H

#include <array>

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include "flexprobe-data.h"

namespace ipxp {

struct FrameSignature : public RecordExt, public std::array<unsigned char, 18> {
   static int REGISTERED_ID;

   FrameSignature() : RecordExt(REGISTERED_ID), std::array<unsigned char, 18>()
   {
   }

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
       if (sizeof(Flexprobe::FrameSignature) > size) {
           return -1;
       }
       std::copy(begin(), end(), buffer);

       return sizeof(Flexprobe::FrameSignature);
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_FLEXPROBE_DATA_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_template;
   }
};

class FlexprobeDataProcessing : public ProcessPlugin
{
public:
    FlexprobeDataProcessing() = default;

    void init(const char *params) {}
    void close() {}
    RecordExt *get_ext() const { return new FrameSignature(); }
    OptionsParser *get_parser() const { return new OptionsParser("flexprobe-data", "Parse flexprobe data (Flexprobe HW only)"); }
    std::string get_name() const { return "flexprobe-data"; }
    FlexprobeDataProcessing *copy() override
    {
        return new FlexprobeDataProcessing(*this);
    }

    int post_create(Flow &rec, const Packet &pkt) override
    {
        if (!pkt.custom) {
            return 0;
        }

        if (!rec.get_extension(FrameSignature::REGISTERED_ID)) {
            auto *fs = new FrameSignature();
            auto data_view = reinterpret_cast<const Flexprobe::FlexprobeData*>(pkt.custom);
            std::copy(data_view->frame_signature.begin(), data_view->frame_signature.end(), fs->begin());
            rec.add_extension(fs);
        }
        return 0;
    }
};

}
#endif //IPFIXPROBE_FLEXPROBE_DATA_PROCESSING_H
