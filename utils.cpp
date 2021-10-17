#include <string>
#include <utility>

#include <ipfixprobe/utils.hpp>

namespace ipxp {

void parse_range(const std::string &arg, std::string &from, std::string &to, const std::string &delim)
{
   size_t pos = arg.find(delim);
   if (pos == std::string::npos) {
      throw std::invalid_argument(arg);
   }

   if (delim.find("-") != std::string::npos) {
      size_t tmp = arg.find_first_not_of(" \t\r\n");
      if (arg[tmp] == '-') {
         tmp = arg.find(delim, pos + 1);
         if (tmp != std::string::npos) {
            pos = tmp;
         }
      }
   }

   from = arg.substr(0, pos);
   to = arg.substr(pos + 1);
   trim_str(from);
   trim_str(to);
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
