/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, CESNET z.s.p.o.
 */

/**
 * \file nettisa.hpp
 * \brief Class for creating NetTiSA flow.
 * \author Josef Koumar koumajos@fit.cvut.cz
 * \date 2023
 */

#ifndef IPXP_PROCESS_NETTISA_HPP
#define IPXP_PROCESS_NETTISA_HPP

#include <cstring>
#include <vector>
#include <utility>
#include <math.h> 

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define NETTISA_UNIREC_TEMPLATE "NTS_MEAN,NTS_MIN,NTS_MAX,NTS_STDEV,NTS_KURTOSIS,NTS_ROOT_MEAN_SQUARE,NTS_AVERAGE_DISPERSION,NTS_MEAN_SCALED_TIME,NTS_MEAN_DIFFTIMES,NTS_MIN_DIFFTIMES,NTS_MAX_DIFFTIMES,NTS_TIME_DISTRIBUTION,NTS_SWITCHING_RATIO"

UR_FIELDS (
   float NTS_MEAN,
   uint16_t NTS_MIN,
   uint16_t NTS_MAX,
   float NTS_STDEV,
   float NTS_KURTOSIS,
   float NTS_ROOT_MEAN_SQUARE,
   float NTS_AVERAGE_DISPERSION,
   float NTS_MEAN_SCALED_TIME,
   float NTS_MEAN_DIFFTIMES,
   float NTS_MIN_DIFFTIMES,
   float NTS_MAX_DIFFTIMES,
   float NTS_TIME_DISTRIBUTION,
   float NTS_SWITCHING_RATIO,
)

/**
 * \brief Flow record extension header for storing parsed NETTISA data.
 */
struct RecordExtNETTISA : public RecordExt {
   static int REGISTERED_ID;

   float mean;
   uint16_t min;
   uint16_t max;
   float stdev;
   float kurtosis;
   float root_mean_square;
   float average_dispersion;
   float mean_scaled_time;
   float mean_difftimes;
   float min_difftimes;
   float max_difftimes;
   float time_distribution;
   float switching_ratio;

   uint16_t prev_payload;
   long prev_time;
    
   RecordExtNETTISA() : RecordExt(REGISTERED_ID)
   {
       mean = 0;
       min = 0;
       max = 0;
       stdev = 0;
       kurtosis = 0;
       root_mean_square = 0;
       average_dispersion = 0;
       mean_scaled_time = 0;
       mean_difftimes = 0;
       min_difftimes = 0;
       max_difftimes = 0;
       time_distribution = 0;
       switching_ratio = 0;
    
       prev_payload = 0;
       prev_time = 0;
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, NTS_MEAN, mean);
      ur_set(tmplt, record, NTS_MIN, min);
      ur_set(tmplt, record, NTS_MAX, max);
      ur_set(tmplt, record, NTS_STDEV, stdev);
      ur_set(tmplt, record, NTS_KURTOSIS, kurtosis);
      ur_set(tmplt, record, NTS_ROOT_MEAN_SQUARE, root_mean_square);
      ur_set(tmplt, record, NTS_AVERAGE_DISPERSION, average_dispersion);
      ur_set(tmplt, record, NTS_MEAN_SCALED_TIME, mean_scaled_time);
      ur_set(tmplt, record, NTS_MEAN_DIFFTIMES, mean_difftimes);
      ur_set(tmplt, record, NTS_MIN_DIFFTIMES, min_difftimes);
      ur_set(tmplt, record, NTS_MAX_DIFFTIMES, max_difftimes);
      ur_set(tmplt, record, NTS_TIME_DISTRIBUTION, time_distribution);
      ur_set(tmplt, record, NTS_SWITCHING_RATIO, switching_ratio);
   }

   const char *get_unirec_tmplt() const
   {
      return NETTISA_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      uint16_t len_mean               = sizeof(mean);
      uint16_t len_min                = sizeof(min);
      uint16_t len_max                = sizeof(max);
      uint16_t len_stdev              = sizeof(stdev);
      uint16_t len_kurtosis           = sizeof(kurtosis);
      uint16_t len_root_mean_square   = sizeof(root_mean_square);
      uint16_t len_average_dispersion = sizeof(average_dispersion);
      uint16_t len_mean_scaled_time   = sizeof(mean_scaled_time);
      uint16_t len_mean_difftimes     = sizeof(mean_difftimes);
      uint16_t len_min_difftimes      = sizeof(min_difftimes);
      uint16_t len_max_difftimes      = sizeof(max_difftimes);
      uint16_t len_time_distribution  = sizeof(time_distribution);
      uint16_t len_switching_ratio   = sizeof(switching_ratio);
      int pos = 0;

      if (len_mean + len_min + len_max + len_stdev + len_kurtosis + len_root_mean_square + len_average_dispersion + len_mean_scaled_time + len_mean_difftimes + len_min_difftimes + len_max_difftimes + len_time_distribution + len_switching_ratio > size) {
         return -1;
      }

      *(float *) (buffer + pos) = htonl(mean);
      pos += len_mean;
      *(uint16_t *) (buffer + pos) = htonl(min);
      pos += len_min;
      *(uint16_t *) (buffer + pos) = htonl(max);
      pos += len_max;
      *(float *) (buffer + pos) = htonl(stdev);
      pos += len_stdev;
      *(float *) (buffer + pos) = htonl(kurtosis);
      pos += len_kurtosis;
      *(float *) (buffer + pos) = htonl(root_mean_square);
      pos += len_root_mean_square;
      *(float *) (buffer + pos) = htonl(average_dispersion);
      pos += len_average_dispersion;
      *(float *) (buffer + pos) = htonl(mean_scaled_time);
      pos += len_mean_scaled_time;
      *(float *) (buffer + pos) = htonl(mean_difftimes);
      pos += len_mean_difftimes;
      *(float *) (buffer + pos) = htonl(min_difftimes);
      pos += len_min_difftimes;
      *(float *) (buffer + pos) = htonl(max_difftimes);
      pos += len_max_difftimes;
      *(float *) (buffer + pos) = htonl(time_distribution);
      pos += len_time_distribution;
      *(float *) (buffer + pos) = htonl(switching_ratio);
      pos += len_switching_ratio;
      return pos;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_NETTISA_TEMPLATE(IPFIX_FIELD_NAMES)
         NULL
      };
      return ipfix_template;
   }
};

// double compute_stdev(const double & mean, const vector<int> & data);


/**
 * \brief Process plugin for parsing packets for the NetTiSA flow.
 */
class NETTISAPlugin : public ProcessPlugin
{
public:
   NETTISAPlugin();
   ~NETTISAPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("nettisa", "Parse NerTiSA flow"); }
   std::string get_name() const { return "nettisa"; }
   RecordExt *get_ext() const { return new RecordExtNETTISA(); }
   ProcessPlugin *copy();

   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void update_record(RecordExtNETTISA *nettisa_data, const Packet &pkt);
   void pre_export(Flow &rec);
};

}
#endif /* IPXP_PROCESS_NETTISA_HPP */