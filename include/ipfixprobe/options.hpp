#ifndef IPXP_OPTIONS_HPP
#define IPXP_OPTIONS_HPP

#include <vector>
#include <map>
#include <functional>
#include <stdexcept>
#include <string>
#include <iostream>

namespace ipxp {

class OptionsParser
{
public:
   static const char DELIM = ';';
   typedef std::function<bool(const char *opt)> OptionParserFunc;
   enum OptionFlags : uint32_t {
      RequiredArgument = 1,
      OptionalArgument = 2,
      NoArgument = 4
   };

   OptionsParser();
   OptionsParser(const std::string &name, const std::string &info);
   ~OptionsParser();
   OptionsParser(OptionsParser &p) = delete;
   OptionsParser(OptionsParser &&p) = delete;
   void operator=(OptionsParser &p) = delete;
   void operator=(OptionsParser &&p) = delete;
   void parse(const char *args) const;
   void parse(int argc, const char *argv[]) const;
   void usage(std::ostream &os, int indentation = 0, std::string mod_name = "") const;

protected:
   std::string m_name;
   std::string m_info;
   char m_delim;
   struct Option {
      std::string m_short;
      std::string m_long;
      std::string m_hint;
      std::string m_description;
      OptionParserFunc m_parser;
      OptionFlags m_flags;
   };
   std::vector<Option *> m_options;
   std::map<std::string, Option *> m_long;
   std::map<std::string, Option *> m_short;

   void register_option(std::string arg_short, std::string arg_long, std::string arg_hint, std::string description, OptionParserFunc parser, OptionFlags flags=OptionFlags::RequiredArgument);
};

class ParserError : public std::runtime_error
{
public:
   explicit ParserError(const std::string &msg) : std::runtime_error(msg) {};
   explicit ParserError(const char *msg) : std::runtime_error(msg) {};
};

}
#endif /* IPXP_OPTIONS_HPP */
