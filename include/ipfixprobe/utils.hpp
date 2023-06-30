/**
 * \file utils.hpp
 * \brief Utility functions
 * \author Jiri Havranek <havranek@cesnet.cz>
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
 *
 *
 */

#ifndef IPXP_UTILS_HPP
#define IPXP_UTILS_HPP

#include <type_traits>
#include <set>
#include <string>
#include <limits>
#include <cctype>
#include <utility>
#include <algorithm>
#include <stdexcept>
#include <cstdint>

namespace ipxp {

void parse_range(const std::string &arg, std::string &from, std::string &to, const std::string &delim = "-");
bool str2bool(std::string str);
void trim_str(std::string &str);
uint32_t variable2ipfix_buffer(uint8_t* buffer2write, uint8_t* buffer2read, uint16_t len);

template<typename T> constexpr
T const& max(const T &a, const T &b) {
  return a > b ? a : b;
}

/*
 * \brief Count number of '1' bits
 * \param [in] num Number to count ones in
 * \return Number of ones counted
 */
template<typename T>
static constexpr unsigned bitcount(T num)
{
   static_assert(!std::is_signed<T>(), "bitcount function is for unsigned types only");
   return num == 0 ? 0 : (bitcount<T>(num >> 1) + (num & 1));
}

template <typename T>
static constexpr bool is_fpoint()
{
   return std::is_floating_point<T>();
}

template <typename T>
static constexpr bool is_uint()
{
   return std::is_integral<T>() && std::is_unsigned<T>();
}

template <typename T>
static constexpr bool is_sint()
{
   return std::is_integral<T>() && std::is_signed<T>();
}

// Use of SFINAE to implement specific conversion function variants

template <typename T>
T str2num(std::string str, typename std::enable_if<is_fpoint<T>()>::type * = nullptr)
{
   size_t pos;
   double tmp;

   trim_str(str);
   try {
      tmp = std::stold(str, &pos);
   } catch (std::out_of_range &e) {
      throw std::invalid_argument(str);
   }
   if (pos != str.size() ||
      tmp < std::numeric_limits<T>::min() ||
      tmp > std::numeric_limits<T>::max()) {
      throw std::invalid_argument(str);
   }

   return static_cast<T>(tmp);
}

template <typename T>
T str2num(std::string str, typename std::enable_if<is_sint<T>()>::type * = nullptr)
{
   long long tmp;
   size_t pos;

   trim_str(str);
   try {
      tmp = std::stoll(str, &pos, 0);
   } catch (std::out_of_range &e) {
      throw std::invalid_argument(str);
   }
   if (pos != str.size() ||
      tmp < std::numeric_limits<T>::min() ||
      tmp > std::numeric_limits<T>::max()) {
      throw std::invalid_argument(str);
   }

   return static_cast<T>(tmp);
}

template <typename T>
T str2num(std::string str, typename std::enable_if<is_uint<T>()>::type * = nullptr)
{
   unsigned long long tmp;
   size_t pos;

   trim_str(str);
   try {
      tmp = std::stoull(str, &pos, 0);
   } catch (std::out_of_range &e) {
      throw std::invalid_argument(str);
   }
   if (pos != str.size() ||
      tmp < std::numeric_limits<T>::min() ||
      tmp > std::numeric_limits<T>::max()) {
      throw std::invalid_argument(str);
   }

   return static_cast<T>(tmp);
}

}
#endif /* IPXP_UTILS_HPP */
