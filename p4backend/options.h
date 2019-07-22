/**
 * \file options.h
 * \brief Header file with compiler options.
 * \date 2019
 * \author Jiri Havranek <havranek@cesnet.cz>
 */
/*
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
*/

#ifndef _BACKENDS_P4E_OPTIONS_H_
#define _BACKENDS_P4E_OPTIONS_H_

#include <getopt.h>
#include <string>

#include "frontends/common/options.h"

#define MAJOR_NUMBER 1
#define MINOR_NUMBER 1
#define BUGFIX_NUMBER 0

/**
 * \brief Backend options and parameters.
 */
class P4EOptions : public CompilerOptions
{
 public:
   std::string genDir_; /**< Directory where source codes will be generated. */
   std::string templatesDir_; /**< Path to directory with templates of exporter code. */

   std::string get_plain_version_number()
   {
      return std::to_string(MAJOR_NUMBER) + "." + std::to_string(MINOR_NUMBER) + "." + std::to_string(BUGFIX_NUMBER);
   }

   std::string get_version()
   {
      return "P4-EXPORTER tool version: " + get_plain_version_number();
   }

   P4EOptions() : genDir_("exporter"), templatesDir_("templates")
   {
      langVersion = CompilerOptions::FrontendVersion::P4_16;
      registerUsage(("This program translates the P4.16 program into flow exporter. All related P4 types should be included in the program.\n"
         + get_version()).c_str());
      registerOption("--gen-dir", "dir", [this](const char *arg){genDir_ = arg; return true;}, "Output directory with generated files.");
      registerOption("--template-dir", "dir", [this](const char *arg){templatesDir_ = arg; return true;}, "Input directory with template files.");
   }
};

#endif // _BACKENDS_P4E_OPTIONS_H_
