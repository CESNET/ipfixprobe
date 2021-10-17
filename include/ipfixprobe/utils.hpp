#ifndef IPXP_UTILS_H
#define IPXP_UTILS_H

#include <type_traits>
#include <set>
#include <string>
#include <limits>
#include <cctype>
#include <utility>
#include <algorithm>
#include <stdexcept>

#include <iostream>
namespace ipxp {

void parse_range(const std::string &arg, std::string &from, std::string &to, const std::string &delim = "-");
bool str2bool(std::string str);
void trim_str(std::string &str);

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
#endif /* IPXP_UTILS_H */
