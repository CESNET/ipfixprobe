#ifndef IPXP_UTILS_H
#define IPXP_UTILS_H

#include <type_traits>
#include <set>
#include <string>
#include <vector>
#include <cctype>
#include <utility>
#include <algorithm>
#include <stdexcept>

namespace ipxp {

typedef std::vector<std::pair<std::string, std::string>> ArgsPairs;

void parseRange(const std::string &arg, std::string &from, std::string &to, const std::string &delim = "-");
ArgsPairs parseArgs(const std::string &args);
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
   return num == 0 ? 0 : (bitcount<T>(num >> 1) + (num & 1));
}

template <typename T>
T str2num(std::string str)
{
   T val;
   size_t pos;

   static_assert(std::is_arithmetic<T>());

   if (std::is_integral<T>()) {
      if (std::is_signed<T>()) {
         val = static_cast<T>(std::stoll(str, &pos, 0));
      } else {
         val = static_cast<T>(std::stoull(str, &pos, 0));
      }
   } else {
      val = static_cast<T>(std::stold(str, &pos));
   }
   if (pos != str.size()) {
      throw std::invalid_argument(str);
   }

   return val;
}

}
#endif /* IPXP_UTILS_H */
