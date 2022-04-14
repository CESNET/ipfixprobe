/**
 * \file flexprobe-encryption-processing.h
 * \brief Traffic feature processing for encryption analysis for Flexprobe -- HW accelerated network probe
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

#ifndef IPFIXPROBE_FLEXPROBE_ENCRYPTION_PROCESSING_H
#define IPFIXPROBE_FLEXPROBE_ENCRYPTION_PROCESSING_H

#include <memory>
#include <limits>
#include <cmath>

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

#include <zmq.hpp>

#include "flexprobe-data.h"
#include "tls.hpp"

namespace ipxp {
    template<typename T> class RtStats
    {
    protected:
        // helper variables for variance calculation
    //    T prev_average_;
        T delta_sq_sum_;

        T mean_;
        T variance_;
        T deviation_;

        T minimum_;
        T maximum_;

    public:
        T mean() const {
            return mean_;
        }

        T variance() const {
            return variance_;
        }

        T deviation() const {
            return deviation_;
        }

        T minimum() const {
            return minimum_;
        }

        T maximum() const {
            return maximum_;
        }

    protected:
        // running average
        T running_average_(T next_value, std::uint64_t packets)
        {
    //        prev_average_ = mean_;
            auto p_delta = next_value - mean_;
            mean_ = packets ? (next_value + static_cast<T>((packets - 1)) * mean_) / static_cast<T>(packets) : T();
            auto delta = next_value - mean_;
            delta_sq_sum_ += p_delta * delta;
            return mean_;
        }

        // running variance calculated using Welford's algorithm
        T running_variance_(std::uint64_t packets)
        {
            return (variance_ = packets ? delta_sq_sum_ / static_cast<T>(packets) : T()), variance_;
        }

        // running deviation
        T comp_deviation_()
        {
            return deviation_ = std::sqrt(variance_), deviation_;
        }

        T comp_minimum_(T next_val) {
            return minimum_ = std::min(minimum_, next_val), minimum_;
        }

        T comp_maximum_(T next_val) {
            return maximum_ = std::max(maximum_, next_val), maximum_;
        }

    public:
        explicit RtStats(T init_min = std::numeric_limits<T>::max(), T init_max = std::numeric_limits<T>::min())
        : delta_sq_sum_(0),
          mean_(0),
          variance_(0),
          deviation_(0),
          minimum_(init_min),
          maximum_(init_max)
        {}

        void update(T next_val, const size_t count)
        {
            running_average_(next_val, count);
            running_variance_(count);
            comp_deviation_();
            comp_minimum_(next_val);
            comp_maximum_(next_val);
        }
    };

    struct FlexprobeEncryptionData : public RecordExt {
        static int REGISTERED_ID;

        std::uint64_t mpe8_valid_count[2];
        std::uint64_t mpe4_valid_count[2];
        RtStats<float> time_interpacket[2];
        RtStats<std::uint16_t> payload_size[2];
        RtStats<float> mpe_8bit[2];
        RtStats<float> mpe_4bit[2];
        bool classification_result;

        FlexprobeEncryptionData() : RecordExt(REGISTERED_ID), mpe8_valid_count(), mpe4_valid_count() {}

        virtual int fill_ipfix(uint8_t *buffer, int size)
        {
           // TODO: fill fields in correct order
            if (sizeof(std::uint8_t) > size) {
                return -1;
            }
            *buffer = static_cast<std::uint8_t>(classification_result ? 1 : 0);
            return 0;
        }

        const char **get_ipfix_tmplt() const
        {
           static const char *ipfix_template[] = {
                 IPFIX_FLEXPROBE_ENCR_TEMPLATE(IPFIX_FIELD_NAMES)
                 nullptr
           };
           return ipfix_template;
        }
    };

    struct FlexprobeClassificationSample
    {
        float interpacket_interval_var_fwd;
        float mpe_8bit_max_fwd;
        float mpe_4bit_mean_fwd;
        float mpe_4bit_dev_fwd;
        float mpe_4bit_min_fwd;
        float mpe_4bit_max_fwd;
        std::uint32_t payload_bytes_mean_fwd;
        std::uint32_t payload_bytes_var_fwd;
        std::uint32_t payload_bytes_min_fwd;
        std::uint32_t payload_bytes_max_fwd;
        std::uint32_t packets_fwd;
        float mpe_4bit_min_reverse;

        FlexprobeClassificationSample()
        :    interpacket_interval_var_fwd(0),
             mpe_8bit_max_fwd(0),
             mpe_4bit_mean_fwd(0),
             mpe_4bit_dev_fwd(0),
             mpe_4bit_min_fwd(0),
             mpe_4bit_max_fwd(0),
             payload_bytes_mean_fwd(0),
             payload_bytes_var_fwd(0),
             payload_bytes_min_fwd(0),
             payload_bytes_max_fwd(0),
             packets_fwd(0),
             mpe_4bit_min_reverse(0)
        {}

        explicit FlexprobeClassificationSample(const FlexprobeEncryptionData& fed) : packets_fwd(0)
        {
            interpacket_interval_var_fwd = fed.time_interpacket[0].variance();
            mpe_8bit_max_fwd = fed.mpe_8bit[0].maximum();
            mpe_4bit_mean_fwd = fed.mpe_4bit[0].mean();
            mpe_4bit_dev_fwd = fed.mpe_4bit[0].deviation();
            mpe_4bit_min_fwd = fed.mpe_4bit[0].minimum();
            mpe_4bit_max_fwd = fed.mpe_4bit[0].maximum();
            payload_bytes_mean_fwd = fed.payload_size[0].mean();
            payload_bytes_var_fwd = fed.payload_size[0].variance();
            payload_bytes_min_fwd = fed.payload_size[0].minimum();
            payload_bytes_max_fwd = fed.payload_size[0].maximum();
            mpe_4bit_min_reverse = fed.mpe_4bit[1].minimum();
        }

    };

    class FlexprobeEncryptionProcessingOptParser : public OptionsParser
    {
    private:
        std::string zmq_path_;

    public:
        FlexprobeEncryptionProcessingOptParser() : OptionsParser("flexprobe-encrypt", "Collect statistical data about flow's behaviour and use them to determine if the flow contains encrypted communication.")
        {
            register_option("p",
                            "path",
                            "PATH",
                            "Path to ZMQ socket of the classification tool. Default: /tmp/ipfixprobe-classify.sock",
                            [this](const char* arg){zmq_path_ = arg; return true;},
                            OptionalArgument);
        }

        std::string zmq_path() const
        {
            return zmq_path_;
        }
    };

    class FlexprobeEncryptionProcessing : public ProcessPlugin
    {
    private:
        std::unique_ptr<zmq::context_t> ctx_;
        std::unique_ptr<zmq::socket_t> link_;

        std::string zmq_path_;
        bool open_zmq_link_()
        {
            if (!ctx_) {
                try {
                    ctx_ = std::make_unique<zmq::context_t>();
                    link_ = std::make_unique<zmq::socket_t>(*ctx_, zmq::socket_type::req);
                    link_->connect("ipc://" + zmq_path_);
                } catch (const zmq::error_t&) {
                    ctx_.reset();
                    link_.reset();
                    return false;
                }
            }
            return true;
        }
    public:
        FlexprobeEncryptionProcessing() = default;
        FlexprobeEncryptionProcessing(const FlexprobeEncryptionProcessing& other) : zmq_path_(other.zmq_path_)
        {
            open_zmq_link_();
        }

        void init(const char *params) override
        {
            FlexprobeEncryptionProcessingOptParser opts;
            opts.parse(params);

            zmq_path_ = opts.zmq_path();
            open_zmq_link_();
        }

        RecordExt *get_ext() const override { return new FlexprobeEncryptionData(); }
        OptionsParser *get_parser() const override { return new FlexprobeEncryptionProcessingOptParser(); }
        std::string get_name() const override { return "flexprobe-encrypt"; }
        FlexprobeEncryptionProcessing *copy() override
        {
            return new FlexprobeEncryptionProcessing(*this);
        }

        int post_create(Flow &rec, const Packet &pkt) override;

        int post_update(Flow& rec, const Packet& pkt) override;

        void pre_export(Flow& rec) override;
    };

}
#endif //IPFIXPROBE_FLEXPROBE_ENCRYPTION_PROCESSING_H
