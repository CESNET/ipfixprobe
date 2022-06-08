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

#include <mlpack/methods/random_forest/random_forest.hpp>
#include <mlpack/methods/decision_tree/decision_tree.hpp>
#include <mlpack/methods/adaboost/adaboost.hpp>

#include "flexprobe-data.h"

namespace ipxp {
    template<typename NumType, NumType Lower, NumType Upper>
    class ConstrainedValue
    {
        static_assert(std::is_arithmetic<NumType>::value, "ConstrainedValue: Only arithmetic type is allowed as NumType.");
    private:
        NumType value_;

    public:
        ConstrainedValue() : value_(Lower)
        {};

        explicit ConstrainedValue(NumType val) : value_(val)
        {
            using namespace std::string_literals;
            if (!(val >= Lower and val <= Upper)) {
                throw std::logic_error(
                        "Assigned value must be in ["s + std::to_string(Lower) + ";" + std::to_string(Upper) +
                        "] range.");
            }
        }

        ConstrainedValue& operator=(const ConstrainedValue& other)
        {
            value_ = other.value_;
            return *this;
        }

        ConstrainedValue& operator=(NumType val)
        {
            using namespace std::string_literals;
            if (!(val >= Lower and val <= Upper)) {
                throw std::logic_error(
                        "Assigned value must be in ["s + std::to_string(Lower) + ";" + std::to_string(Upper) +
                        "] range.");
            }
            value_ = val;
            return *this;
        }

        ConstrainedValue& operator+=(NumType val)
        {
            if (value_ + val > Upper) {
                value_ = Upper;
            } else {
                value_ += val;
            }

            return *this;
        }

        ConstrainedValue& operator-=(NumType val)
        {
            if (value_ - val < Lower) {
                value_ = Lower;
            } else {
                value_ -= val;
            }

            return *this;
        }

        friend std::ostream& operator<<(std::ostream& os, const ConstrainedValue& val)
        {
            os << val.value_;
            return os;
        }

        friend bool operator<(const ConstrainedValue& lhs, const ConstrainedValue& rhs)
        {
            return lhs.value_ < rhs.value_;
        }

        friend bool operator>(const ConstrainedValue& lhs, const ConstrainedValue& rhs)
        {
            return lhs.value_ > rhs.value_;
        }

        friend bool operator<=(const ConstrainedValue& lhs, const ConstrainedValue& rhs)
        {
            return lhs.value_ <= rhs.value_;
        }

        friend bool operator>=(const ConstrainedValue& lhs, const ConstrainedValue& rhs)
        {
            return lhs.value_ >= rhs.value_;
        }

        friend bool operator==(const ConstrainedValue& lhs, const ConstrainedValue& rhs)
        {
            return lhs.value_ == rhs.value_;
        }

        friend bool operator!=(const ConstrainedValue& lhs, const ConstrainedValue& rhs)
        {
            return lhs.value_ != rhs.value_;
        }

        friend bool operator<(const ConstrainedValue& lhs, NumType rhs)
        {
            return lhs.value_ < rhs;
        }

        friend bool operator>(const ConstrainedValue& lhs, NumType rhs)
        {
            return lhs.value_ > rhs;
        }

        friend bool operator<=(const ConstrainedValue& lhs, NumType rhs)
        {
            return lhs.value_ <= rhs;
        }

        friend bool operator>=(const ConstrainedValue& lhs, NumType rhs)
        {
            return lhs.value_ >= rhs;
        }

        friend bool operator==(const ConstrainedValue& lhs, NumType rhs)
        {
            return lhs.value_ == rhs;
        }

        friend bool operator!=(const ConstrainedValue& lhs, NumType rhs)
        {
            return lhs.value_ != rhs;
        }
    };

    template<typename T> class RtStats
    {
        static_assert(std::is_arithmetic<T>::value, "RtStats: Only arithmetic type is allowed as T.");
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
        ssize_t known_protocol_pattern_id;
        unsigned known_protocol_position;
        bool multiple_patterns;
        bool multiple_pattern_occurence;
        bool classification_result;

        FlexprobeEncryptionData()
        : RecordExt(REGISTERED_ID),
          mpe8_valid_count(),
          mpe4_valid_count(),
          known_protocol_pattern_id(-1),
          known_protocol_position(),
          multiple_patterns(),
          multiple_pattern_occurence(),
          classification_result(false)
        {
            mpe_8bit[0] = mpe_8bit[1] = RtStats<float>(0, 0);
            mpe_4bit[0] = mpe_4bit[1] = RtStats<float>(0, 0);
        }

        virtual int fill_ipfix(uint8_t *buffer, int size)
        {
            if (sizeof(std::uint8_t) > static_cast<size_t>(size)) {
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
        std::string model_path_;

    public:
        FlexprobeEncryptionProcessingOptParser() : OptionsParser("flexprobe-encrypt", "Collect statistical data about flow's behaviour and use them to determine if the flow contains encrypted communication.")
        {
            register_option("p",
                            "path",
                            "PATH",
                            "Path to RandomForest model to load.",
                            [this](const char* arg){model_path_ = arg; return true;},
                            RequiredArgument);
        }

        std::string model_path() const
        {
            return model_path_;
        }
    };

    class FlexprobeEncryptionProcessing : public ProcessPlugin
    {
    private:
//        mlpack::tree::RandomForest<> clf_;
        mlpack::adaboost::AdaBoost<mlpack::tree::DecisionTree<>> clf_;
        const std::array<size_t, 2> pi_pattern_lengths;

        enum Scores {
            KNOWN_PATTERN_FOUND = 5,
            KNOWN_PATTERN_AT_THE_BEGINNING = 5,
            MULTIPLE_KNOWN_PATTERNS = 10,
            REPEATING_PATTERN = 10,
            KNOWN_OPEN_PROTOCOL = 20
        };

    public:
        FlexprobeEncryptionProcessing() : ProcessPlugin(), clf_(), pi_pattern_lengths({3, 8}) {}

        void init(const char *params) override
        {
            FlexprobeEncryptionProcessingOptParser opts;
            opts.parse(params);

            if (opts.model_path().empty()) {
                throw PluginError("You must specify ML model to use.");
            }

            mlpack::data::Load(opts.model_path(), "Encrypt Detect", clf_);
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
