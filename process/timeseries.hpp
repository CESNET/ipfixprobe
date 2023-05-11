#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>

#include <fstream>
#include <string>


#include <complex.h>
#include <nfft3.h>
#include <iomanip>


/**
 * \file timeseries.hpp
 * \brief Plugin for parsing timeseries traffic.
 * \author David Kezlinek
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
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
 * This software is provided as is'', and any express or implied
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

#ifndef IPXP_PROCESS_TIMESERIES_HPP
#define IPXP_PROCESS_TIMESERIES_HPP

#include <cstring>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>


#include <map>
#include <vector>
#include <cmath>
#include <algorithm>

#include <complex.h>
#include <nfft3.h>

#define MAX_PACKETS_ARRAY 1000      // < 2^16
#define MAX_PACKETS_HISTOGRAM 1000   // < 2^16
#define MAX_TIME 3600000000  //=1h           // < 2^32
#define MIN_PACKETS_NFFT 2 
#define NFFT_OVERSAMPLING_FACTOR  5.0   //(double)
#define NFFT_HIGHEST_FREQ_FACTOR  6.0    //(double)

#define TS_FLUSH_WHEN_FULL false     //Tell storage plugin to flush (immediately export) current flow if max packet array/histogram/time is full.

namespace ipxp {

    /// @brief Data structure to store the resulting attributes obtained from time series analysis
    struct TS_statistics_result{
        float TS_MEAN = 0;
        float TS_STDEV = 0;
        float TS_VAR = 0;
        float TS_BURSTINESS = 0;
        uint16_t TS_Q1 = 0;
        uint16_t TS_MEDIAN = 0;
        uint16_t TS_Q3 = 0;
        uint16_t TS_MIN = 0;
        uint16_t TS_MAX = 0;
        uint16_t TS_MODE = 0;
        float TS_COEFFICIENT_OF_VARIATION = 0;
        float TS_AVERAGE_DISPERSION = 0;
        float TS_PERCENT_DEVIATION = 0;
        float TS_ROOT_MEAN_SQUARE = 0;
        float TS_PERCENT_BELOW_MEAN = 0;
        float TS_PERCENT_ABOVE_MEAN = 0;
        float TS_PEARSON_SK1_SKEWNESS = 0;
        float TS_PEARSON_SK2_SKEWNESS = 0;
        float TS_FISHER_MI_3_SKEWNESS = 0;
        float TS_GALTON_SKEWNESS = 0;
        float TS_KURTOSIS = 0;
        float TS_ENTROPY = 0;
        float TS_SCALED_ENTROPY = 0;
        float TS_P_BENFORD = 0;
    };
    /// @brief Data structure to store the resulting attributes obtained from time series analysis
    struct TS_time_result{

        float TS_MEAN_SCALED_TIME = 0;
        float TS_MEDIAN_SCALED_TIME = 0;
        float TS_Q1_SCALED_TIME = 0;
        float  TS_Q3_SCALED_TIME = 0;
        uint32_t TS_DURATION = 0;

        uint32_t TS_MIN_DIFFTIMES = 0;
        uint32_t TS_MAX_DIFFTIMES = 0;

        float TS_MEAN_DIFFTIMES = 0;
        uint32_t TS_MEDIAN_DIFFTIMES = 0;
        float TS_DIFFTIMES_SKEWNESS = 0;//PEARSON_SK2_SKEWNESS
        float TS_DIFFTIMES_KURTOSIS = 0;
        float TS_TIME_DISTRIBUTION = 0;
    };
    
    /// @brief Data structure to store the resulting attributes obtained from time series analysis
    struct TS_behavior_result{
        float TS_HURST_EXPONENT = 0.5f;
        float TS_SWITCHING_METRIC = 0;
        float TS_DIRECTIONS = 1;
        uint32_t TS_PERIODICITY_TIME = 0;
        uint16_t TS_PERIODICITY_VAL = 0;
        
    };

    /// @brief Data structure to store the resulting attributes obtained from time series analysis    
    struct TS_frequency_result{
        float TS_MIN_POWER = 0;
        float TS_MAX_POWER = 0;
        float TS_MIN_POWER_FREQ = 0;
        float TS_MAX_POWER_FREQ = 0;
        float TS_SPECTRAL_ENERGY = 0;
        float TS_SPECTRAL_ENTROPY = 0;
        float TS_SPECTRAL_KURTOSIS = 0;
        float TS_SPECTRAL_SKEWNESS = 0; //
        float TS_SPECTRAL_ROLLOFF = 0;
        float TS_SPECTRAL_CENTROID = 0;
        float TS_SPECTRAL_SPREAD = 0;
        float TS_SPECTRAL_SLOPE = 0; //
        float TS_SPECTRAL_CREST = 0;
        float TS_SPECTRAL_FLUX = 0;
        float TS_SPECTRAL_BANDWIDTH = 0;
        float TS_POWER_MEAN = 0;
        float TS_POWER_STD = 0;
        float TS_PERIODICITY_SCDF = 0;
    };
    struct TS_results
    {
        TS_statistics_result *statistics = nullptr;
        TS_time_result *time = nullptr;
        TS_behavior_result *behavior = nullptr;
        TS_frequency_result *frequency = nullptr;

        ~TS_results(){
            delete (statistics);
            delete (time);
            delete (behavior);
            delete (frequency);
        }
    };



struct RecordExtTIMESERIES; 

/// @brief Data structure for storing packet sizes
class PacketLengths{
public:
    virtual ~PacketLengths(){};

    /// @brief Add size of packet to datastructure.
    /// @param PacketLength size of packet payload <= 1500
    /// @return false if container is full
    virtual bool add(uint16_t PacketLength) = 0;
    
    /// @brief Get histogram of timeseries
    /// @return histogram <size of packet, count>
    virtual std::vector<std::pair<uint16_t, uint16_t>> getHistogram() const = 0;

    /// @brief Get sum of size of all packets in datastructure.
    virtual uint32_t getFlowSize() const = 0;
    virtual uint16_t getPacketCount() const = 0;
};

/// @brief Data structure for storing packet sizes in array
class PacketLengthsArray : public PacketLengths{
public:
    PacketLengthsArray(){m_packet_lengths.reserve(100);}
    ~PacketLengthsArray() {}

    bool add(uint16_t PacketLength) override{
        m_packet_lengths.push_back(PacketLength);
        m_flow_size += PacketLength;
        return (m_packet_lengths.size() >= MAX_PACKETS_ARRAY);
    }

    std::vector<std::pair<uint16_t, uint16_t>> getHistogram() const;
    uint32_t getFlowSize() const { return m_flow_size; }
    uint16_t getPacketCount() const { return m_packet_lengths.size(); }
    const std::vector<uint16_t> &getSizeValues() const{ return m_packet_lengths;}

private:
    std::vector<uint16_t> m_packet_lengths;
    uint32_t m_flow_size = 0;
};

class PacketLengthsSmall;

/// @brief Data structure for storing packet sizes in histogram
class PacketLengthsHistogram : public PacketLengths{
public:
    PacketLengthsHistogram(){}
    PacketLengthsHistogram(PacketLengthsSmall *tmp, uint16_t PacketLength);

    bool add(uint16_t PacketLength) override{
        m_Histogram[PacketLength]++;
        m_flow_size += PacketLength;
        m_packet_count++;
        return (m_packet_count >= MAX_PACKETS_HISTOGRAM);
    }

    std::vector<std::pair<uint16_t, uint16_t>> getHistogram() const;
    uint32_t getFlowSize() const { return m_flow_size; }
    uint16_t getPacketCount() const { return m_packet_count; }

private:
    uint16_t m_Histogram[1501] = {0};
    uint16_t m_packet_count = 0;
    uint32_t m_flow_size = 0;
};

/// @brief Data structure for storing packet sizes in small histogram
class PacketLengthsSmall : public PacketLengths
{
public:
    PacketLengthsSmall(RecordExtTIMESERIES *rec):m_record(rec){}

    bool add(uint16_t PacketLength) override;

    inline const uint16_t get_bin(uint16_t i) const { return m_bin[i]; }
    inline const uint16_t get_frequency(uint16_t i) const { return m_frequency[i]; }

    std::vector<std::pair<uint16_t, uint16_t>> getHistogram() const;
    uint32_t getFlowSize() const { return (((uint32_t)m_bin[0] * m_frequency[0]) + ((uint32_t)m_bin[1] * m_frequency[1])); }
    uint16_t getPacketCount() const { return m_frequency[0] + m_frequency[1]; }

private:
    RecordExtTIMESERIES *m_record;
    uint16_t m_bin[2] = {0};
    uint16_t m_frequency[2] = {0};
    uint8_t m_unique_count = 0;
};

/// @brief Data structure for storing incoming packet time in array
class PacketTimes{
    std::vector<uint32_t> m_time_data;

public:
    PacketTimes() { m_time_data.reserve(100); }
    
    bool Add(uint32_t time) { 
        m_time_data.push_back(time); 
        return (m_time_data.size() >= MAX_PACKETS_ARRAY || time >= MAX_TIME); 
    }
    
    TS_time_result *calculateTime() const;
    const std::vector<uint32_t> &getTimeValues() const {return m_time_data;}
};


#define TIMESERIES_UNIREC_TEMPLATE "TS_MEAN,TS_STDEV,TS_VAR,TS_BURSTINESS,TS_Q1,TS_MEDIAN,TS_Q3,TS_MIN,TS_MAX,TS_MODE,TS_COEFFICIENT_OF_VARIATION,TS_AVERAGE_DISPERSION,TS_PERCENT_DEVIATION,TS_ROOT_MEAN_SQUARE,TS_PERCENT_BELOW_MEAN,TS_PERCENT_ABOVE_MEAN,TS_PEARSON_SK1_SKEWNESS,TS_PEARSON_SK2_SKEWNESS,TS_FISHER_MI_3_SKEWNESS,TS_GALTON_SKEWNESS,TS_KURTOSIS,TS_ENTROPY,TS_SCALED_ENTROPY,TS_P_BENFORD,TS_MEAN_SCALED_TIME,TS_MEDIAN_SCALED_TIME,TS_Q1_SCALED_TIME, TS_Q3_SCALED_TIME,TS_DURATION,TS_MIN_DIFFTIMES,TS_MAX_DIFFTIMES,TS_MEAN_DIFFTIMES,TS_MEDIAN_DIFFTIMES,TS_DIFFTIMES_SKEWNESS,TS_DIFFTIMES_KURTOSIS,TS_TIME_DISTRIBUTION,TS_HURST_EXPONENT,TS_SWITCHING_METRIC,TS_DIRECTIONS,TS_PERIODICITY_TIME,TS_PERIODICITY_VAL,TS_MIN_POWER,TS_MAX_POWER,TS_MIN_POWER_FREQ,TS_MAX_POWER_FREQ,TS_SPECTRAL_ENERGY,TS_SPECTRAL_ENTROPY,TS_SPECTRAL_KURTOSIS,TS_SPECTRAL_SKEWNESS,TS_SPECTRAL_ROLLOFF,TS_SPECTRAL_CENTROID,TS_SPECTRAL_SPREAD,TS_SPECTRAL_SLOPE,TS_SPECTRAL_CREST,TS_SPECTRAL_FLUX,TS_SPECTRAL_BANDWIDTH,TS_POWER_MEAN,TS_POWER_STD,TS_PERIODICITY_SCDF" 

UR_FIELDS (
        float TS_MEAN,
        float TS_STDEV,
        float TS_VAR,
        float TS_BURSTINESS,
        uint16 TS_Q1,
        uint16 TS_MEDIAN,
        uint16 TS_Q3,
        uint16 TS_MIN,
        uint16 TS_MAX,
        uint16 TS_MODE,
        float TS_COEFFICIENT_OF_VARIATION,
        float TS_AVERAGE_DISPERSION,
        float TS_PERCENT_DEVIATION,
        float TS_ROOT_MEAN_SQUARE,
        float TS_PERCENT_BELOW_MEAN,
        float TS_PERCENT_ABOVE_MEAN,
        float TS_PEARSON_SK1_SKEWNESS,
        float TS_PEARSON_SK2_SKEWNESS,
        float TS_FISHER_MI_3_SKEWNESS,
        float TS_GALTON_SKEWNESS,
        float TS_KURTOSIS,
        float TS_ENTROPY,
        float TS_SCALED_ENTROPY,
        float TS_P_BENFORD,
        float TS_MEAN_SCALED_TIME,
        float TS_MEDIAN_SCALED_TIME,
        float TS_Q1_SCALED_TIME,
        float  TS_Q3_SCALED_TIME,
        uint32 TS_DURATION,
        uint32 TS_MIN_DIFFTIMES,
        uint32 TS_MAX_DIFFTIMES,
        float TS_MEAN_DIFFTIMES,
        uint32 TS_MEDIAN_DIFFTIMES,
        float TS_DIFFTIMES_SKEWNESS,
        float TS_DIFFTIMES_KURTOSIS,
        float TS_TIME_DISTRIBUTION,
        float TS_HURST_EXPONENT,
        float TS_SWITCHING_METRIC,
        float TS_DIRECTIONS,
        uint32 TS_PERIODICITY_TIME,
        uint16 TS_PERIODICITY_VAL,
        float TS_MIN_POWER,
        float TS_MAX_POWER,
        float TS_MIN_POWER_FREQ,
        float TS_MAX_POWER_FREQ,
        float TS_SPECTRAL_ENERGY,
        float TS_SPECTRAL_ENTROPY,
        float TS_SPECTRAL_KURTOSIS,
        float TS_SPECTRAL_SKEWNESS,
        float TS_SPECTRAL_ROLLOFF,
        float TS_SPECTRAL_CENTROID,
        float TS_SPECTRAL_SPREAD,
        float TS_SPECTRAL_SLOPE,
        float TS_SPECTRAL_CREST,
        float TS_SPECTRAL_FLUX,
        float TS_SPECTRAL_BANDWIDTH,
        float TS_POWER_MEAN,
        float TS_POWER_STD,
        float TS_PERIODICITY_SCDF
)

/**
 * \brief Flow record extension header for storing parsed TIMESERIES data.
 */
struct RecordExtTIMESERIES : public RecordExt {
    TS_results * Result =nullptr;
    PacketLengths * SizeData =nullptr;
    PacketTimes * TimeData =nullptr;
    uint16_t Switching =0;
    uint16_t Directions=1;
    bool LastDirection =true;
    bool Full = false;
    const bool Statistics,Time,Behavior,Frequency;
    
    static int REGISTERED_ID;
    static bool IPFIXSetuped;
    static char *ipfix_template[100];


  RecordExtTIMESERIES(bool statistics,bool time,bool behavior,bool frequency) : RecordExt(REGISTERED_ID),Statistics(statistics),Time(time),Behavior(behavior),Frequency(frequency)
  {
    if(Statistics || Behavior || Frequency){
        if(!(Behavior || Frequency)){
        SizeData = new PacketLengthsSmall(this);
        }else{
        SizeData = new PacketLengthsArray;
        }
    }
    if(Time || Behavior || Frequency){
      TimeData = new PacketTimes;
    }

    if(!IPFIXSetuped){
        int gpos =0;
        if(Statistics){
            int pos =0;
            char * tmp[] = {IPFIX_TIMESERIES_STATISTICS_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
            while(tmp[pos] != NULL){
                ipfix_template[gpos] = tmp[pos];
                gpos++;
                pos++;
            }
        }
        if(Time){
            int pos =0;
            char * tmp[] = {IPFIX_TIMESERIES_TIME_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
            while(tmp[pos] != NULL){
                ipfix_template[gpos] = tmp[pos];
                gpos++;
                pos++;
            }
        }
        if(Behavior){
            int pos =0;
            char * tmp[] = {IPFIX_TIMESERIES_BEHAVIOR_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
            while(tmp[pos] != NULL){
                ipfix_template[gpos] = tmp[pos];
                gpos++;
                pos++;
            }
        }
        if(Frequency){
            int pos =0;
            char * tmp[] = {IPFIX_TIMESERIES_FREQUENCY_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
            while(tmp[pos] != NULL){
                ipfix_template[gpos] = tmp[pos];
                gpos++;
                pos++;
            }
        }
        ipfix_template[gpos] = NULL;
        IPFIXSetuped=true;
    }


  }
  ~RecordExtTIMESERIES(){      
       delete(Result);
       delete(SizeData);
       delete(TimeData);
  }
  

    bool isSizeRequired(){return (Statistics || Behavior || Frequency);}
    bool isTimeRequired(){return (Time || Behavior || Frequency);}
    bool useHistogram(){return !(Behavior || Frequency);}
    
    /// @brief Calculate all atributes from timeseries.
    /// @return true if succes
    bool calculateResult();





#ifdef WITH_NEMEA
    virtual void fill_unirec(ur_template_t *tmplt, void *record){
        if(Result == nullptr)
            return;
    
        if(Statistics){
            if (Result->statistics == nullptr)
                return;

            ur_set(tmplt, record, F_TS_MEAN, Result->statistics->TS_MEAN);
            ur_set(tmplt, record, F_TS_STDEV, Result->statistics->TS_STDEV);
            ur_set(tmplt, record, F_TS_VAR, Result->statistics->TS_VAR);
            ur_set(tmplt, record, F_TS_BURSTINESS, Result->statistics->TS_BURSTINESS);
            ur_set(tmplt, record, F_TS_Q1, Result->statistics->TS_Q1);
            ur_set(tmplt, record, F_TS_MEDIAN, Result->statistics->TS_MEDIAN);
            ur_set(tmplt, record, F_TS_Q3, Result->statistics->TS_Q3);
            ur_set(tmplt, record, F_TS_MIN, Result->statistics->TS_MIN);
            ur_set(tmplt, record, F_TS_MAX, Result->statistics->TS_MAX);
            ur_set(tmplt, record, F_TS_MODE, Result->statistics->TS_MODE);
            ur_set(tmplt, record, F_TS_COEFFICIENT_OF_VARIATION, Result->statistics->TS_COEFFICIENT_OF_VARIATION);
            ur_set(tmplt, record, F_TS_AVERAGE_DISPERSION, Result->statistics->TS_AVERAGE_DISPERSION);
            ur_set(tmplt, record, F_TS_PERCENT_DEVIATION, Result->statistics->TS_PERCENT_DEVIATION);
            ur_set(tmplt, record, F_TS_ROOT_MEAN_SQUARE, Result->statistics->TS_ROOT_MEAN_SQUARE);
            ur_set(tmplt, record, F_TS_PERCENT_BELOW_MEAN, Result->statistics->TS_PERCENT_BELOW_MEAN);
            ur_set(tmplt, record, F_TS_PERCENT_ABOVE_MEAN, Result->statistics->TS_PERCENT_ABOVE_MEAN);
            ur_set(tmplt, record, F_TS_PEARSON_SK1_SKEWNESS, Result->statistics->TS_PEARSON_SK1_SKEWNESS);
            ur_set(tmplt, record, F_TS_PEARSON_SK2_SKEWNESS, Result->statistics->TS_PEARSON_SK2_SKEWNESS);
            ur_set(tmplt, record, F_TS_FISHER_MI_3_SKEWNESS, Result->statistics->TS_FISHER_MI_3_SKEWNESS);
            ur_set(tmplt, record, F_TS_GALTON_SKEWNESS, Result->statistics->TS_GALTON_SKEWNESS);
            ur_set(tmplt, record, F_TS_KURTOSIS, Result->statistics->TS_KURTOSIS);
            ur_set(tmplt, record, F_TS_ENTROPY, Result->statistics->TS_ENTROPY);
            ur_set(tmplt, record, F_TS_SCALED_ENTROPY, Result->statistics->TS_SCALED_ENTROPY);
            ur_set(tmplt, record, F_TS_P_BENFORD, Result->statistics->TS_P_BENFORD);
        }
        if(Time){
            if(Result->time == nullptr)
                return;

        ur_set(tmplt, record, F_TS_MEAN_SCALED_TIME, Result->time->TS_MEAN_SCALED_TIME);
        ur_set(tmplt, record, F_TS_MEDIAN_SCALED_TIME, Result->time->TS_MEDIAN_SCALED_TIME);
        ur_set(tmplt, record, F_TS_Q1_SCALED_TIME, Result->time->TS_Q1_SCALED_TIME);
        ur_set(tmplt, record, F_TS_Q3_SCALED_TIME, Result->time->TS_Q3_SCALED_TIME);
        ur_set(tmplt, record, F_TS_DURATION, Result->time->TS_DURATION);

        ur_set(tmplt, record, F_TS_MIN_DIFFTIMES, Result->time->TS_MIN_DIFFTIMES);
        ur_set(tmplt, record, F_TS_MAX_DIFFTIMES, Result->time->TS_MAX_DIFFTIMES);

        ur_set(tmplt, record, F_TS_MEAN_DIFFTIMES, Result->time->TS_MEAN_DIFFTIMES);
        ur_set(tmplt, record, F_TS_MEDIAN_DIFFTIMES, Result->time->TS_MEDIAN_DIFFTIMES);
        ur_set(tmplt, record, F_TS_DIFFTIMES_SKEWNESS, Result->time->TS_DIFFTIMES_SKEWNESS);
        ur_set(tmplt, record, F_TS_DIFFTIMES_KURTOSIS, Result->time->TS_DIFFTIMES_KURTOSIS);
        ur_set(tmplt, record, F_TS_TIME_DISTRIBUTION, Result->time->TS_TIME_DISTRIBUTION);
        }


        if(Behavior){
            if(Result->behavior == nullptr)
                return;

        ur_set(tmplt, record, F_TS_HURST_EXPONENT, Result->behavior->TS_HURST_EXPONENT);
        ur_set(tmplt, record, F_TS_SWITCHING_METRIC, Result->behavior->TS_SWITCHING_METRIC);
        ur_set(tmplt, record, F_TS_DIRECTIONS, Result->behavior->TS_DIRECTIONS);
        ur_set(tmplt, record, F_TS_PERIODICITY_TIME, Result->behavior->TS_PERIODICITY_TIME);
        ur_set(tmplt, record, F_TS_PERIODICITY_VAL, Result->behavior->TS_PERIODICITY_VAL);
        }

        if(Frequency){
            if(Result->frequency == nullptr)
                return;

        ur_set(tmplt, record, F_TS_MIN_POWER, Result->frequency->TS_MIN_POWER);
        ur_set(tmplt, record, F_TS_MAX_POWER, Result->frequency->TS_MAX_POWER);
        ur_set(tmplt, record, F_TS_MIN_POWER_FREQ, Result->frequency->TS_MIN_POWER_FREQ);
        ur_set(tmplt, record, F_TS_MAX_POWER_FREQ, Result->frequency->TS_MAX_POWER_FREQ);
        ur_set(tmplt, record, F_TS_SPECTRAL_ENERGY, Result->frequency->TS_SPECTRAL_ENERGY);
        ur_set(tmplt, record, F_TS_SPECTRAL_ENTROPY, Result->frequency->TS_SPECTRAL_ENTROPY);
        ur_set(tmplt, record, F_TS_SPECTRAL_KURTOSIS, Result->frequency->TS_SPECTRAL_KURTOSIS);
        ur_set(tmplt, record, F_TS_SPECTRAL_SKEWNESS, Result->frequency->TS_SPECTRAL_SKEWNESS);
        ur_set(tmplt, record, F_TS_SPECTRAL_ROLLOFF, Result->frequency->TS_SPECTRAL_ROLLOFF);
        ur_set(tmplt, record, F_TS_SPECTRAL_CENTROID, Result->frequency->TS_SPECTRAL_CENTROID);
        ur_set(tmplt, record, F_TS_SPECTRAL_SPREAD, Result->frequency->TS_SPECTRAL_SPREAD);
        ur_set(tmplt, record, F_TS_SPECTRAL_SLOPE, Result->frequency->TS_SPECTRAL_SLOPE);
        ur_set(tmplt, record, F_TS_SPECTRAL_CREST, Result->frequency->TS_SPECTRAL_CREST);
        ur_set(tmplt, record, F_TS_SPECTRAL_FLUX, Result->frequency->TS_SPECTRAL_FLUX);
        ur_set(tmplt, record, F_TS_SPECTRAL_BANDWIDTH, Result->frequency->TS_SPECTRAL_BANDWIDTH);
        ur_set(tmplt, record, F_TS_POWER_MEAN, Result->frequency->TS_POWER_MEAN);
        ur_set(tmplt, record, F_TS_POWER_STD, Result->frequency->TS_POWER_STD);
        ur_set(tmplt, record, F_TS_PERIODICITY_SCDF, Result->frequency->TS_PERIODICITY_SCDF);
        }
    return;

   }

   const char *get_unirec_tmplt() const{
        return TIMESERIES_UNIREC_TEMPLATE;
    }
#endif

    virtual int fill_ipfix(uint8_t *buffer, int size){
        int sizeToWrite = Statistics * sizeof(TS_statistics_result) + Time * sizeof(TS_time_result) + Behavior* (sizeof(TS_behavior_result) -2) + Frequency* sizeof(TS_frequency_result);
        int pos=0;
        if(size <= sizeToWrite || Result == nullptr)
            return -1;
        
        float * tmp =nullptr;
        if(Statistics){
            if (Result->statistics == nullptr)
                return -1;
            

            tmp =&Result->statistics->TS_MEAN; //to mute warning  -Wstrict-aliasing
            *(uint32_t *) (buffer + 0 )  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_STDEV;
            *(uint32_t *) (buffer + 4 )  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_VAR;
            *(uint32_t *) (buffer + 8 )  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_BURSTINESS;
            *(uint32_t *) (buffer + 12 )  = ntohl(*(uint32_t*)tmp);
            *(uint16_t *) (buffer + 16)  = ntohs(Result->statistics->TS_Q1);
            *(uint16_t *) (buffer + 18)  = ntohs(Result->statistics->TS_MEDIAN);
            *(uint16_t *) (buffer + 20)  = ntohs(Result->statistics->TS_Q3);
            *(uint16_t *) (buffer + 22)  = ntohs(Result->statistics->TS_MIN);
            *(uint16_t *) (buffer + 24)  = ntohs(Result->statistics->TS_MAX);
            *(uint16_t *) (buffer + 26)  = ntohs(Result->statistics->TS_MODE);
            tmp =&Result->statistics->TS_COEFFICIENT_OF_VARIATION;
            *(uint32_t *) (buffer + 28)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_AVERAGE_DISPERSION;
            *(uint32_t *) (buffer + 32)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_PERCENT_DEVIATION;
            *(uint32_t *) (buffer + 36)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_ROOT_MEAN_SQUARE;
            *(uint32_t *) (buffer + 40)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_PERCENT_BELOW_MEAN;
            *(uint32_t *) (buffer + 44)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_PERCENT_ABOVE_MEAN;;
            *(uint32_t *) (buffer + 48)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_PEARSON_SK1_SKEWNESS;
            *(uint32_t *) (buffer + 52)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_PEARSON_SK2_SKEWNESS;
            *(uint32_t *) (buffer + 56)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_FISHER_MI_3_SKEWNESS;
            *(uint32_t *) (buffer + 60)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_GALTON_SKEWNESS;
            *(uint32_t *) (buffer + 64)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_KURTOSIS;
            *(uint32_t *) (buffer + 68)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_ENTROPY;
            *(uint32_t *) (buffer + 72)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_SCALED_ENTROPY;
            *(uint32_t *) (buffer + 76)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->statistics->TS_P_BENFORD;
            *(uint32_t *) (buffer + 80)  = ntohl(*(uint32_t*)tmp);
    
                pos+= 84;
        }
        
        if(Time){
            if(Result->time == nullptr)
                return -1;
            tmp =&Result->time->TS_MEAN_SCALED_TIME;
            *(uint32_t *) (buffer + pos + 0)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->time->TS_MEDIAN_SCALED_TIME;
            *(uint32_t *) (buffer + pos + 4)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->time->TS_Q1_SCALED_TIME;
            *(uint32_t *) (buffer + pos + 8)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->time->TS_Q3_SCALED_TIME;
            *(uint32_t *) (buffer + pos + 12)  = ntohl(*(uint32_t*)tmp);
            *(uint32_t *) (buffer + pos + 16)  = ntohl(Result->time->TS_DURATION);
            *(uint32_t *) (buffer + pos + 20)  = ntohl(Result->time->TS_MIN_DIFFTIMES);
            *(uint32_t *) (buffer + pos + 24)  = ntohl(Result->time->TS_MAX_DIFFTIMES);
            tmp =&Result->time->TS_MEAN_DIFFTIMES;
            *(uint32_t *) (buffer + pos + 28)  = ntohl(*(uint32_t*)tmp);
            *(uint32_t *) (buffer + pos + 32)  = ntohl(Result->time->TS_MEDIAN_DIFFTIMES);
            tmp =&Result->time->TS_DIFFTIMES_SKEWNESS;
            *(uint32_t *) (buffer + pos + 36)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->time->TS_DIFFTIMES_KURTOSIS;
            *(uint32_t *) (buffer + pos + 40)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->time->TS_TIME_DISTRIBUTION;
            *(uint32_t *) (buffer + pos + 44)  = ntohl(*(uint32_t*)tmp);
            pos+= 48;
        }
        if(Behavior){
            if(Result->behavior == nullptr)
                return -1;

            tmp =&Result->behavior->TS_HURST_EXPONENT;
            *(uint32_t *) (buffer + pos + 0)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->behavior->TS_SWITCHING_METRIC;
            *(uint32_t *) (buffer + pos + 4)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->behavior->TS_DIRECTIONS;
            *(uint32_t *) (buffer + pos + 8)  = ntohl(*(uint32_t*)tmp);

            *(uint32_t *) (buffer + pos + 12)  = ntohl(*(uint32_t*)&Result->behavior->TS_PERIODICITY_TIME);
            *(uint16_t *) (buffer + pos + 16)  = ntohs(Result->behavior->TS_PERIODICITY_VAL);

            pos+=18;
        }
        if(Frequency){
            if(Result->frequency == nullptr)
                return -1;

            tmp = &Result->frequency->TS_MIN_POWER;   
            *(uint32_t *) (buffer + pos + 0)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_MAX_POWER;
            *(uint32_t *) (buffer + pos + 4)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_MIN_POWER_FREQ;
            *(uint32_t *) (buffer + pos + 8)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_MAX_POWER_FREQ;
            *(uint32_t *) (buffer + pos + 12)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_ENERGY;
            *(uint32_t *) (buffer + pos + 16)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_ENTROPY;
            *(uint32_t *) (buffer + pos + 20)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_KURTOSIS;
            *(uint32_t *) (buffer + pos + 24)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_SKEWNESS;
            *(uint32_t *) (buffer + pos + 28)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_ROLLOFF;
            *(uint32_t *) (buffer + pos + 32)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_CENTROID;
            *(uint32_t *) (buffer + pos + 36)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_SPREAD;
            *(uint32_t *) (buffer + pos + 40)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_SLOPE;
            *(uint32_t *) (buffer + pos + 44)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_CREST;
            *(uint32_t *) (buffer + pos + 48)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_FLUX;
            *(uint32_t *) (buffer + pos + 52)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_SPECTRAL_BANDWIDTH;
            *(uint32_t *) (buffer + pos + 56)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_POWER_MEAN;
            *(uint32_t *) (buffer + pos + 60)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_POWER_STD;
            *(uint32_t *) (buffer + pos + 64)  = ntohl(*(uint32_t*)tmp);
            tmp =&Result->frequency->TS_PERIODICITY_SCDF;
            *(uint32_t *) (buffer + pos + 68)  = ntohl(*(uint32_t*)tmp);
            
        }
            

        

      return sizeToWrite;
   }

    const char **get_ipfix_tmplt() const{     
        return (const char **)ipfix_template;
    }


     private:   

/* Computation of the positive frequency
 part of the (unnormalised ) Fourier
 transform of a times -series (t, y).

 Input:
 t the times reduced to [1/2, 1/2)
* y the measurements (NULL, for
* computing the FT of the window)
* n the number of measurements
* m the number of positive frequencies
* Output:
* d the Fourier coefficients
* (preallocated array for (m+1)
* elements)
*/
void nfft(const double *t, const double *y,int n, int m, double _Complex *d)const;

struct LS
{
    LS(int size){
        freqs = new double[size];
        Pn = new double[size];
        nfreqs = size;
    }
    ~LS(){
        delete[] freqs;
        delete[] Pn;
    }

    double *freqs; // (>0) frequencies
    double *Pn;    // periodogram ordinates
    int nfreqs;    // number of frequencies
};

inline double square(double in)const{ return in * in;}

template <typename T>
inline int sgn(T val)const{return (T(0) < val) - (val < T(0));}

inline double sign(double a, double b)const{return std::abs(a) * sgn(b);}

/* Computes the Lomb-Scargle normalised periodogram of a times -series.
 *
 * t the times, reduced to [-1/2,1/2).
 * y the measurements , centred around <y>.
 * npts the length of the times -series.
 * over the oversampling factor.
 * hifac the highest frequency in units of "average" Nyquist frequency.
 *
 * This function returns the results in a structure, LS (see text).
 */
LS *periodogram(const double *t, const double *y, int npts, double over, double hifac, double var)const;

// Function to transform the TimeSeries data to the format required by the periodogram function
LS *computePeriodogram(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value, double oversampling_factor, double highest_freq_factor)const;



double PolyFit1D(const double *x_data, const double *y_data, const size_t size, const double x_mean, const double y_mean)const;

/// @brief Get slope of line
/// @param x_data
/// @param y_data 
/// @param size  site of array x_data
/// @return 
double PolyFit1D(const double *x_data, const double *y_data, const size_t size)const;

double LogPolyFit1D(const double *x_data, const double *y_data, const size_t size)const;

double calculateHurstExponent(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value)const;

double calculateHurstExponent(const std::vector<uint16_t> &data)const;




TS_statistics_result *calculateStatistics(const std::vector<std::pair<uint16_t, uint16_t>> &Histogram)const;

TS_behavior_result *calculatePeriodicity(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value, const std::vector<std::pair<uint16_t, uint16_t>> &Histogram);

TS_behavior_result *calculateBehavior(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value, const std::vector<std::pair<uint16_t, uint16_t>> &Histogram);

TS_frequency_result *calculateFrequency(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value);

};



class TIMESERIESParser : public OptionsParser
{
public:
   bool Statistics,Time,Behavior,Frequency;

   TIMESERIESParser() : OptionsParser("timeseries", "Processing plugin"),Statistics(false),Time(false),Behavior(false),Frequency(false)
   {
        register_option("s", "statistics", "", "Calculate Statistics features", [this](const char *arg){Statistics = true; return true;}, OptionFlags::NoArgument);
        register_option("t", "time", "", "Calculate Time features", [this](const char *arg){Time = true; return true;}, OptionFlags::NoArgument);
        register_option("b", "behavior", "", "Calculate Behavior features", [this](const char *arg){Behavior = true; return true;}, OptionFlags::NoArgument);
        register_option("f", "frequency", "", "Calculate Frequency features", [this](const char *arg){Frequency = true; return true;}, OptionFlags::NoArgument);
   }
   bool useDefault(){return !(Statistics || Time || Behavior || Frequency);}
};

/**
 * \brief Process plugin for parsing TIMESERIES packets.
 */
class TIMESERIESPlugin : public ProcessPlugin
{
public:
   TIMESERIESPlugin();
   ~TIMESERIESPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new TIMESERIESParser(); }
   std::string get_name() const { return "timeseries"; }
   RecordExt *get_ext() const { return new RecordExtTIMESERIES(Statistics,Time,Behavior,Frequency); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void pre_export(Flow &rec);

private:
    bool Statistics,Time,Behavior,Frequency;

};

}
#endif /* IPXP_PROCESS_TIMESERIES_HPP */
