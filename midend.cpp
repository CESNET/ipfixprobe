/**
 * \file midend.cpp
 * \brief Implementation of the compiler's midend optimizations.
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

#include "midend.h"
#include "frontends/common/constantFolding.h"
#include "frontends/common/resolveReferences/resolveReferences.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/fromv1.0/v1model.h"
#include "frontends/p4/moveDeclarations.h"
#include "frontends/p4/simplify.h"
#include "frontends/p4/simplifyParsers.h"
#include "frontends/p4/strengthReduction.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "frontends/p4/typeMap.h"
#include "frontends/p4/uniqueNames.h"
#include "frontends/p4/unusedDeclarations.h"
#include "midend/actionSynthesis.h"
#include "midend/complexComparison.h"
#include "midend/convertEnums.h"
#include "midend/copyStructures.h"
#include "midend/eliminateTuples.h"
#include "midend/eliminateNewtype.h"
#include "midend/eliminateSerEnums.h"
#include "midend/local_copyprop.h"
#include "midend/nestedStructs.h"
#include "midend/removeLeftSlices.h"
#include "midend/removeParameters.h"
#include "midend/removeUnusedParameters.h"
#include "midend/simplifyKey.h"
#include "midend/simplifySelectCases.h"
#include "midend/simplifySelectList.h"
#include "midend/removeSelectBooleans.h"
#include "midend/validateProperties.h"
#include "midend/compileTimeOps.h"
#include "midend/orderArguments.h"
#include "midend/predication.h"
#include "midend/expandLookahead.h"
#include "midend/expandEmit.h"
#include "midend/tableHit.h"
#include "midend/midEndLast.h"

namespace P4E {

class EnumOn32Bits : public P4::ChooseEnumRepresentation {
   cstring filename;
   bool convert(const IR::Type_Enum* type) const override {
      if (type->srcInfo.isValid()) {
         auto sourceFile = type->srcInfo.getSourceFile();
         if (sourceFile.endsWith(filename))
            // Don't convert any of the standard enums
            return false;
      }
      return true;
   }
   unsigned enumSize(unsigned) const override
   { return 32; }

public:
   explicit EnumOn32Bits(cstring filename) : filename(filename) { }
};

const IR::ToplevelBlock *MidEnd::run(P4EOptions &options, const IR::P4Program *program)
{
   if (program == nullptr) {
      return nullptr;
   }

   bool isv1 = options.langVersion == CompilerOptions::FrontendVersion::P4_14;
   refMap.setIsV1(isv1);
   auto evaluator = new P4::EvaluatorPass(&refMap, &typeMap);

   auto convertEnums = new P4::ConvertEnums(&refMap, &typeMap, new EnumOn32Bits("v1model.p4"));
   PassManager midEnd = {
      new P4::EliminateNewtype(&refMap, &typeMap),
      new P4::EliminateSerEnums(&refMap, &typeMap),
      new P4::RemoveActionParameters(&refMap, &typeMap),
      convertEnums,
      new P4::OrderArguments(&refMap, &typeMap),
      new P4::TypeChecking(&refMap, &typeMap),
      new P4::SimplifyKey(&refMap, &typeMap,
                        new P4::OrPolicy(
                              new P4::IsValid(&refMap, &typeMap),
                              new P4::IsMask())),
      new P4::ConstantFolding(&refMap, &typeMap),
      new P4::StrengthReduction(&refMap, &typeMap),
      new P4::SimplifySelectCases(&refMap, &typeMap, true),  // require constant keysets
      new P4::ExpandLookahead(&refMap, &typeMap),
      new P4::ExpandEmit(&refMap, &typeMap),
      new P4::SimplifyParsers(&refMap),
      new P4::StrengthReduction(&refMap, &typeMap),
      new P4::EliminateTuples(&refMap, &typeMap),
      new P4::SimplifyComparisons(&refMap, &typeMap),
      new P4::CopyStructures(&refMap, &typeMap),
      new P4::NestedStructs(&refMap, &typeMap),
      new P4::SimplifySelectList(&refMap, &typeMap),
      new P4::RemoveSelectBooleans(&refMap, &typeMap),
      new P4::Predication(&refMap),
      new P4::MoveDeclarations(),  // more may have been introduced
      new P4::ConstantFolding(&refMap, &typeMap),
      new P4::LocalCopyPropagation(&refMap, &typeMap),
      new P4::ConstantFolding(&refMap, &typeMap),
      new P4::MoveDeclarations(),
      new P4::ValidateTableProperties({ "implementation",
                                       "size",
                                       "counters",
                                       "meters",
                                       "support_timeout" }),
      new P4::SimplifyControlFlow(&refMap, &typeMap),
      new P4::CompileTimeOperations(),
      new P4::TableHit(&refMap, &typeMap),
      new P4::RemoveLeftSlices(&refMap, &typeMap),

      isv1 ? new P4::RemoveUnusedActionParameters(&refMap) : nullptr,

      new P4::TypeChecking(&refMap, &typeMap),
      new P4::MidEndLast(),
      evaluator,
   };

   midEnd.setName("MidEnd");
   midEnd.addDebugHooks(hooks);
   program = program->apply(midEnd);
   if (::errorCount() > 0) {
      return nullptr;
   }

   return evaluator->getToplevelBlock();
}

}  // namespace P4E
