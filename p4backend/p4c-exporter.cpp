/**
 * \file p4c-exporter.cpp
 * \brief Main code of P4 exporter compiler extension.
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

#include <stdio.h>
#include <string>
#include <iostream>

#include <nlohmann/json.hpp>
#include <inja/inja.hpp>

#include "ir/ir.h"
#include "lib/log.h"
#include "lib/crash.h"
#include "lib/exceptions.h"
#include "lib/gc.h"
#include "lib/error.h"
#include "lib/nullstream.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/common/applyOptionsPragmas.h"
#include "frontends/common/parseInput.h"
#include "frontends/p4/frontend.h"

#include "midend.h"
#include "options.h"
#include "utils.h"

#include "types.h"
#include "parser.h"
#include "cache.h"
#include "exporter.h"
#include "plugin.h"

using P4CEContext = P4CContextWithOptions<P4EOptions>;

void runBackend(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
{
   if (topLevel == nullptr) {
      return;
   }

   if (topLevel->getMain() == nullptr) {
      ::error("Could not locate top-level block; is there a %1% module?", IR::P4Program::main);
      return;
   }

   if (!exporter::generateOutputFolder(options.genDir_)) {
      return;
   }

   exporter::log("Compiling types");
   exporter::TypesGenerator typesGen(options, topLevel, refMap, typeMap);
   typesGen.generate();

   if (::errorCount() > 0) {
      return;
   }

   exporter::log("Compiling parser");
   exporter::ParserGenerator parserGen(options, topLevel, refMap, typeMap);
   parserGen.generate();

   if (::errorCount() > 0) {
      return;
   }

   if (options.parserOnly_) {
      return;
   }

   exporter::log("Compiling cache");
   exporter::CacheGenerator cacheGen(options, topLevel, refMap, typeMap);
   cacheGen.generate();

   if (::errorCount() > 0) {
      return;
   }

   exporter::log("Compiling exporter");
   exporter::ExporterGenerator exporterGen(options, topLevel, refMap, typeMap);
   exporterGen.generate();

   exporter::log("Compiling plugins");
   exporter::PluginGenerator pluginGen(options, topLevel, refMap, typeMap);
   pluginGen.generate();


   if (::errorCount() > 0) {
      return;
   }

   if (!exporter::fileExists(options.templatesDir_ + "/main.c.tmplt")) {
      ::error("template file main.c.tmplt could not be read");
      return;
   }

   // Create main.c and Makefile.
   nlohmann::json dummy;
   inja::Environment env = inja::Environment(options.templatesDir_ + "/", options.genDir_ + "/");
   inja::Template tmpltMain = env.parse_template("main.c.tmplt");
   env.write(tmpltMain, dummy, "main.c");

   exporter::copy(options.templatesDir_ + "/Makefile.am", options.genDir_ + "/Makefile.am");
   exporter::copy(options.templatesDir_ + "/configure.ac", options.genDir_ + "/configure.ac");
   exporter::copy(options.templatesDir_ + "/bootstrap.sh", options.genDir_ + "/bootstrap.sh");
   exporter::copy(options.templatesDir_ + "/README.md", options.genDir_ + "/README.md");
}

void compile(P4EOptions &options)
{
   auto hook = options.getDebugHook();
   auto program = P4::parseP4File(options);
   if (::errorCount() > 0) {
      return;
   }

   P4::P4COptionPragmaParser optionsPragmaParser;
   program->apply(P4::ApplyOptionsPragmas(optionsPragmaParser));

   P4::FrontEnd frontend;
   frontend.addDebugHook(hook);
   program = frontend.run(options, program);
   if (::errorCount() > 0) {
      return;
   }

   P4E::MidEnd midend;
   midend.addDebugHook(hook);
   auto toplevel = midend.run(options, program);
   if (options.dumpJsonFile) {
      JSONGenerator(*openFile(options.dumpJsonFile, true)) << program << std::endl;
   }
   if (::errorCount() > 0) {
      return;
   }

   runBackend(options, toplevel, &midend.refMap, &midend.typeMap);
}

int main(int argc, char *argv[])
{
   setup_gc_logging();
   setup_signals();

   AutoCompileContext autoP4CContext(new P4CEContext);
   P4EOptions& options = P4CEContext::get().options();

   options.langVersion = CompilerOptions::FrontendVersion::P4_16;
   options.compilerVersion = "0.0.1";

   if (options.process(argc, argv) != nullptr) {
      options.setInputFile();
   }
   if (::errorCount() > 0) {
      exit(1);
   }

   try {
      compile(options);
   } catch (const Util::P4CExceptionBase &bug) {
      std::cerr << bug.what() << std::endl;
      return 1;
   }

   return ::errorCount() > 0;
}
