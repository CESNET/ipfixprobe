#include <string>
#include <vector>
#include <utility>

#include <ipfixprobe/utils.hpp>

namespace ipxp {

void parseRange(const std::string &arg, std::string &from, std::string &to, const std::string &delim)
{
   size_t pos = arg.find(delim);
   if (pos == std::string::npos) {
      throw std::invalid_argument(arg);
   }

   from = arg.substr(0, pos);
   to = arg.substr(pos + 1);
}

bool str2bool(std::string str)
{
   std::set<std::string> accepted_values = {"y", "yes", "t", "true", "on", "1"};
   trim_str(str);
   std::transform(str.begin(), str.end(), str.begin(), ::tolower);
   return accepted_values.find(str) != accepted_values.end();
}

void trim_str(std::string &str)
{
   str.erase(0, str.find_first_not_of(" \t\n\r"));
   str.erase(str.find_last_not_of(" \t\n\r") + 1);
}

}
