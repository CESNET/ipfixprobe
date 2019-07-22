/**
 * \file types.cpp
 * \brief Contains P4 types code generation objects.
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

#include <nlohmann/json.hpp>
#include <inja/inja.hpp>

#include "ir/ir.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#include "options.h"
#include "utils.h"
#include "types.h"

namespace exporter
{

//
// TypesGenerator
//


TypesGenerator::TypesGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : Generator(options, topLevel, refMap, typeMap)
{
}

void TypesGenerator::generate()
{
   // Process global headers.
   for (auto obj : topLevel_->getProgram()->objects) {
      if (obj->is<IR::Type_Struct>() || obj->is<IR::Type_Header>() || obj->is<IR::Type_HeaderUnion>()) {
         TypeTranslator type(obj->to<IR::Type>(), typeMap_);
         nlohmann::json tmp;
         if (type.getNameShort() == "flowrec_s") {
            nlohmann::json ext;
            nlohmann::json first;
            nlohmann::json last;
            nlohmann::json id;
            nlohmann::json parent;

            fillJsonTypeBasic(ext, "struct flowext_s *", "flowext_s", typeStruct);
            fillJsonTypeBasic(first, "struct timeval", "timeval", typeStruct);
            fillJsonTypeBasic(last, "struct timeval", "timeval", typeStruct);
            fillJsonTypeBasic(id, "uint64_t", "uint64_t", typeIntU);
            fillJsonTypeBasic(parent, "uint64_t", "uint64_t", typeIntU);
            ext["name"] = "ext";
            first["name"] = "first";
            last["name"] = "last";
            id["name"] = "id";
            parent["name"] = "parent";
            
            tmp["fields"] += ext;
            tmp["fields"] += first;
            tmp["fields"] += last;
            tmp["fields"] += id;
            tmp["fields"] += parent;
         }
         type.fillJson(tmp);

         if (type.getNameShort() == "headers_s") {
            tmp["name"] = "headers";
            types_["parsed_headers"] = tmp;
         } else {
            types_["types"] += tmp;
         }
      } else if (obj->to<IR::Type_Typedef>()) {
         ::error("Typedefs not supported yet");
         return;
      }
   }

   if (errorCount() > 0) {
      return;
   }

   if (!checkTemplateFile(options_.templatesDir_ + "/types.h.tmplt")) {
      return;
   }

   inja::Environment env = inja::Environment(options_.templatesDir_ + "/", options_.genDir_ + "/");
   inja::Template tmpltHeader = env.parse_template("types.h.tmplt");
   env.write(tmpltHeader, types_, "types.h");
}

} // namespace exporter
