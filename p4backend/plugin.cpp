/**
 * \file plugin.cpp
 * \brief Contains plugins code generation objects.
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
#include "frontends/p4/coreLibrary.h"
#include "frontends/p4/methodInstance.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#include "options.h"
#include "utils.h"

#include "plugin.h"

namespace exporter {

static std::string compiledPluginName;


//
// PluginExpressionHelper
//

PluginExpressionHelper::PluginExpressionHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : ConstructLogicalExpression(refMap, typeMap)
{
   setName("PluginExpressionHelper");
}

bool PluginExpressionHelper::preorder(const IR::Member *expr)
{
   visit(expr->expr);
   expression_ += ".";
   expression_ += expr->member.name.c_str();
   return false;
}

bool PluginExpressionHelper::preorder(const IR::PathExpression *expr)
{
   std::string path = expr->path->name.name.c_str();
   expression_ += path;
   if (path == "ext") {
      expression_ += "[0]";
   } else if (path == "flow") {
      expression_ += "[0]";
   }
   return false;
}

bool PluginExpressionHelper::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "extract_re") {
         compileExtractRe(expr);
         return false;
      } else if (externMethod->method->name.name == "lookahead_re") {
         compileLookaheadRe(expr);
         return false;
      } else if (externMethod->method->name.name == "match") {
         compileMatch(expr);
         return false;
      } else if (externMethod->method->name.name == "lookahead") {
         compileLookahead(expr);
         return false;
      } else if (externMethod->method->name.name == "length") {
         expression_ += "(payload_end - payload)";
         return false;
      } else {
         ::error("Method or function call not supported: %1%", expr);
      }
   } else {
      auto externFunc = methodInst->to<P4::ExternFunction>();
      if (externFunc != nullptr) {
         if (externFunc->method->name.name == "verify") {
            return false;
         }
      }
      ::error("Method or function call not supported: %1%", expr);
   }

   return false;
}

void PluginExpressionHelper::compileExtractRe(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("parse extern method requires 2 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   nlohmann::json dummy;
   LexerBuilder builder(refMap_, typeMap_, dummy);
   expression_ += builder.compileCall(arg1, arg2);
}

void PluginExpressionHelper::compileLookaheadRe(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 1) {
      ::error("lookahead extern method requires 1 argument: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;

   nlohmann::json dummy;
   LexerBuilder builder(refMap_, typeMap_, dummy);
   expression_ += builder.compileCall(arg1, nullptr);
}

void PluginExpressionHelper::compileMatch(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("match extern method requires 2 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   nlohmann::json dummy;
   LexerBuilder builder(refMap_, typeMap_, dummy);
   expression_ += builder.compileCall(arg1, arg2, true);
}

void PluginExpressionHelper::compileLookahead(const IR::MethodCallExpression *expr)
{
   if (expr->typeArguments->size() != 1) {
      ::error("Unable to compile lookahead %1%", expr);
   }

   TypeTranslator type((expr->typeArguments[0])[0], typeMap_);
   uint32_t width = type.getWidth();

   if (width <= 32) {
      std::string loaderFunc = "";
      std::string transformFunc = "";
      uint32_t toLoad;
      getLoadParameters(width, loaderFunc, transformFunc, toLoad);

      unsigned shiftBits = toLoad - width;
      if (shiftBits != 0) {
         expression_ += format("%1%(((%2%)(%3%(payload, 0) >> %4%) & FPP_MASK(%5%, %6%)));",
            transformFunc, type.getName(), loaderFunc, shiftBits, type.getName(), width);
      } else {
         expression_ += format("%1%((%2%)(%3%(payload, 0)));",
            transformFunc, type.getName(), loaderFunc);
      }
   } else {
      ::error("Unable to compile lookahead with more than 32 bits");
   }
}


//
// LexerBuilder
//


LexerBuilder::LexerBuilder(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container)
   : CodeBuilder(refMap, typeMap, container)
{
}

std::string LexerBuilder::compileDefinition(const IR::Expression *arg1, const IR::Expression *arg2, bool extractInput, bool consumeInput, bool matchArguments)
{
   if (!matchArguments) {
      checkNumArgs(arg1, arg2);
   }
   compilePrototype(arg1, arg2, matchArguments);
   compileCode(getRegex(arg1), getParamCnt(arg2), extractInput, consumeInput);

   if (matchArguments && (extractInput || consumeInput)) {
      BUG("cannot match arguments in regex functin and extract or consume input at the same time");
   }

   return compileFuncName(arg1);
}

std::string LexerBuilder::getRegex(const IR::Expression *arg1)
{
   auto path = arg1->to<IR::PathExpression>();

   if (path == nullptr) {
      ::error("expected PathExpression as an first argument of extern method: %1%", arg1);
      return "";
   }

   auto decl = refMap_->getDeclaration(path->path);
   auto regexAnnotation = decl->getAnnotation(ANNOTATION_REGEX);
   if (regexAnnotation == nullptr) {
      ::error("first argument of parse extern method has to be annotated with regex: %1%", arg1);
      return "";
   }

   std::string regex = regexAnnotation->body.at(0)->text.c_str();
   for (size_t i = 0; regex[i]; i++) {
      if (regex[i] == '\\' && regex[i + 1] == '"') {
         regex.erase(i, 1);
      }
   }
   return regex;
}

std::string LexerBuilder::compileFuncName(const IR::Expression *arg1)
{
   std::string regex = getRegex(arg1);
   std::string hash = std::to_string(std::hash<std::string>()(regex));
   return format("regex_%1%_%2%", compiledPluginName, hash);
}

std::string LexerBuilder::compileCall(const IR::Expression *arg1, const IR::Expression *arg2, bool matchArguments)
{
   std::string params;
   if (!matchArguments) {
      params = "payload, payload_end, &payload";
   }
   if (arg2 != nullptr) {
      if (arg2->is<IR::ListExpression>()) {
         if (matchArguments) {
            BUG("matching multiple arguments in regular expression call not supported");
         }
         for (auto e : arg2->to<IR::ListExpression>()->components) {
            if (!(e->is<IR::PathExpression>() || e->is<IR::Member>())) {
               ::error("unexpected node type: %1%", e);
               return "";
            }

            PluginExpressionHelper ins(refMap_, typeMap_);
            e->apply(ins);
            params += format(", %1%, sizeof(%1%)", ins.getExpression());
         }
      } else if (arg2->is<IR::PathExpression>() || arg2->is<IR::Member>()) {
         PluginExpressionHelper ins(refMap_, typeMap_);
         arg2->apply(ins);
         if (!matchArguments) {
            params += format(", %1%, sizeof(%1%)", ins.getExpression());
         } else {
            params += format("%1%, %1% + sizeof(%1%), NULL", ins.getExpression()); // TODO: add 0 sentinel
         }
      } else {
         ::error("unexpected node type: %1%", arg2);
         return "";
      }
   }

   return format("%1%(%2%)", compileFuncName(arg1), params);
}

int LexerBuilder::checkRegex(const char *regex, const char **marker)
{
   int groups = 0;
   char prev1 = 0;
   char prev2 = 0;
   bool squareBrackets = false;
   bool apostrophe = false;
   bool quotationMarks = false;

   for (; *regex; prev2 = prev1, prev1 = *regex, regex++) {
      if (prev1 == '\\' && prev2 != '\\') {
         continue;
      }
      if (!squareBrackets && !apostrophe && !quotationMarks) {
         switch (*regex) {
            case '"':
               quotationMarks = true;
               break;
            case '\'':
               apostrophe = true;
               break;
            case '[':
               squareBrackets = true;
               break;
            default:
               break;
         }
         if (*regex == '(') {
            groups += checkRegex(regex + 1, marker) + 1;
            regex = *marker;
            if (**marker != ')') {
               ::error("found unmatched bracket ) in regex");
               return 0;
            }
         } else if (*regex == ')') {
            *marker = regex;
            return groups;
         }
      } else {
         switch (*regex) {
            case '"':
               quotationMarks = false;
               break;
            case '\'':
               apostrophe = false;
               break;
            case ']':
               squareBrackets = false;
               break;
            default:
               break;
         }
      }
   }

   *marker = regex;
   return groups;
}

bool LexerBuilder::checkNumArgs(const IR::Expression *arg1, const IR::Expression *arg2)
{
   if (arg2 != nullptr) {
      std::string regex = getRegex(arg1);
      int paramCnt = getParamCnt(arg2);

      const char *marker;
      int groupsFound = checkRegex(regex.c_str(), &marker);
      if (::errorCount() > 0) {
         ::error("errors found in '%1%' regex", regex);
         return false;
      } else if (*marker != 0) {
         ::error("errors found in '%1%' regex", regex);
         return false;
      } else if (groupsFound != paramCnt) {
         ::error("number of regex groups and parameter count mismatch: found %1% groups, but got %2% parameter(s) in '%3%' regex", groupsFound, paramCnt, regex);
         return false;
      }
   }
   return true;
}

int LexerBuilder::getParamCnt(const IR::Expression *arg2)
{
   if (arg2 != nullptr) {
      if (arg2->is<IR::ListExpression>()) {
         return arg2->to<IR::ListExpression>()->components.size();
      } else if (arg2->is<IR::PathExpression>() || arg2->is<IR::Member>()) {
         return 1;
      } else {
         ::error("unexpected node type: %1%", arg2);
         return 0;
      }
   }
   return 0;
}

void LexerBuilder::compilePrototype(const IR::Expression *arg1, const IR::Expression *arg2, bool matchArguments)
{
   std::string params = "const uint8_t *payload, const uint8_t *payload_end, const uint8_t **payload_cursor";
   if (!matchArguments) {
      if (arg2 != nullptr) {
         if (arg2->is<IR::ListExpression>()) {
            int paramIndex = 0;

            for (auto e : arg2->to<IR::ListExpression>()->components) {
               if (!(e->is<IR::PathExpression>() || e->is<IR::Member>())) {
                  ::error("unexpected node type: %1%", e);
                  return;
               }

               params += format(", uint8_t *arg%1%, size_t arg%1%_len", paramIndex);
               paramIndex++;
            }
         } else if (arg2->is<IR::PathExpression>() || arg2->is<IR::Member>()) {
            params += format(", uint8_t *arg0, size_t arg0_len");
         } else {
            ::error("unexpected node type: %1%", arg2);
            return;
         }
      }
   }

   std::string func = format("int %1%(%2%)", compileFuncName(arg1), params);
   container_["prototype"] = func;
}

void LexerBuilder::compileCode(const std::string &regex, int paramCnt, bool extractInput, bool consumeInput)
{
   addStatement("const uint8_t *backup;");
   addStatement("const uint8_t *marker;");

   int totalParamCnt = paramCnt + 1;
   addStatement(format("int yynmatch = %1%;", totalParamCnt));
   addStatement(format("const uint8_t *yypmatch[%1%];", totalParamCnt * 2));

   for (int i = 0; i < paramCnt + 1; i++) {
      addStatement(format("const uint8_t *yyt%1%;", i + 1));
   }

   for (int i = 0; i < paramCnt + 1; i++) {
      addStatement(format("(void) yyt%1%;", i + 1));
   }

   addStatement("(void) backup;");
   addStatement("(void) marker;");
   addStatement("(void) yynmatch;");
   addStatement("(void) yypmatch;");

   addStatement("#  define YYCTYPE     uint8_t");
   addStatement("#  define YYPEEK()    (payload < payload_end ? *payload : 0)");
   addStatement("#  define YYSKIP()    ++payload");
   addStatement("#  define YYFILL(n)   return 0;");
   addStatement("#  define YYCURSOR    payload");
   addStatement("#  define YYLIMIT     payload_end");
   addStatement("#  define YYMARKER    marker");
   addStatement("#  define YYBACKUP()  backup = payload");
   addStatement("#  define YYRESTORE() payload = backup");
   addStatement("/*!re2c");
   increaseIndent();
   addStatement("* { return 0; }");
   addStatement(format("%1% {", regex));
   if (extractInput) {
      increaseIndent();
      addStatement("size_t len;");

      for (int i = 0; i < paramCnt; i++) {
         addStatement(format("len = yypmatch[%1%] - yypmatch[%2%];", (i + 1) * 2 + 1, (i + 1) * 2));
         addStatement(format("if (len >= arg%1%_len) {", i));
         increaseIndent();
         addStatement(format("len = arg%1%_len - 1;", i));
         decreaseIndent();
         addStatement(format("}"));
         addStatement(format("memcpy(arg%1%, yypmatch[%2%], len);", i, (i + 1) * 2));
         addStatement(format("arg%1%[len] = 0;", i));
      }

      if (consumeInput) {
         addStatement("*payload_cursor = payload;");
      }
   }

   addStatement("return 1;");
   decreaseIndent();
   addStatement("}");
   decreaseIndent();
   addStatement("*/");
   addStatement("return 0;");
}


//
// LexerHelper
//


LexerHelper::LexerHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container)
   : CodeBuilder(refMap, typeMap, container)
{
   setName("LexerHelper");
}
bool LexerHelper::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();
   if (::errorCount() > 0) {
      return false;
   }
   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "extract_re") {
         compileParse(expr);
         return false;
      } else if (externMethod->method->name.name == "lookahead_re") {
         compileLookahead(expr);
         return false;
      } else if (externMethod->method->name.name == "match") {
         compileMatch(expr);
         return false;
      }
   }

   return false;
}

bool LexerHelper::functionAlreadyCompiled(const std::string &funcName)
{
   return std::find(LexerHelper::compiledFunctions.begin(), LexerHelper::compiledFunctions.end(), funcName)
      != LexerHelper::compiledFunctions.end();
}

void LexerHelper::compileParse(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("parse extern method requires 2 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   nlohmann::json functionContainer;
   LexerBuilder builder(refMap_, typeMap_, functionContainer);

   std::string funcName = builder.compileDefinition(arg1, arg2, true, true);

   if (!functionAlreadyCompiled(funcName)) {
      container_["functions"] += functionContainer;
      LexerHelper::compiledFunctions.push_back(funcName);
   }
}

void LexerHelper::compileLookahead(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 1) {
      ::error("lookahead extern method requires 1 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;

   nlohmann::json functionContainer;
   LexerBuilder builder(refMap_, typeMap_, functionContainer);

   std::string funcName = builder.compileDefinition(arg1, nullptr, false, false);

   if (!functionAlreadyCompiled(funcName)) {
      container_["functions"] += functionContainer;
      LexerHelper::compiledFunctions.push_back(funcName);
   }
}

void LexerHelper::compileMatch(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("match extern method requires 2 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   nlohmann::json functionContainer;
   LexerBuilder builder(refMap_, typeMap_, functionContainer);

   std::string funcName = builder.compileDefinition(arg1, arg2, false, false, true);

   if (!functionAlreadyCompiled(funcName)) {
      container_["functions"] += functionContainer;
      LexerHelper::compiledFunctions.push_back(funcName);
   }
}

std::vector<std::string> LexerHelper::compiledFunctions;


//
// PluginVisitor
//


PluginVisitor::PluginVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container)
   : CodeBuilder(refMap, typeMap, container)
{
   setName("PluginVisitor");
}

bool PluginVisitor::preorder(const IR::P4Parser *p)
{
   addStatement("const uint8_t *payload_end = payload + payload_len;");
   addStatement("(void) payload_end;");
   for (auto decl : p->parserLocals) {
      visit(decl);
   }

   addStatement("goto start;");
   addStatement("goto accept;");
   addStatement("goto reject;");
   for (auto state : p->states) {
      visit(state);
   }
   addStatement("return resultReject;");
   return false;
}

bool PluginVisitor::preorder(const IR::ParserState *s)
{
   std::string name = s->name.name.c_str();
   addStatement(format("%1%: {", name));
   increaseIndent();
   if (name == "flush") {
      addStatement("return resultFlush;");
   } else {
      for (auto tmp : s->components) {
         visit(tmp);
      }

      visit(s->selectExpression);

      if (name == "accept") {
         addStatement("return resultAccept;");
      } else if (name == "reject") {
         addStatement("return resultReject;");
      }
   }
   decreaseIndent();
   addStatement("}");
   return false;
}

bool PluginVisitor::preorder(const IR::AssignmentStatement *s)
{
   PluginExpressionHelper left(refMap_, typeMap_);
   PluginExpressionHelper right(refMap_, typeMap_);
   s->left->apply(left);
   s->right->apply(right);

   addStatement(format("%1% = %2%;", left.getExpression(), right.getExpression()));
   return false;
}

bool PluginVisitor::preorder(const IR::Declaration *s)
{
   auto tmpDecl = dynamic_cast<const IR::Declaration_Variable *>(s);
   if (tmpDecl == nullptr) {
      ::error("unexpected declaration %1%", s);
      return false;
   }
   auto regex = tmpDecl->getAnnotation(ANNOTATION_REGEX);

   if (regex == nullptr) {
      TypeTranslator type(tmpDecl, typeMap_);
      int arrayLen = type.getArrayLength();
      if (arrayLen <= 0) {
         addStatement(format("%1% %2%;", type.getName(), s->name.name.c_str()));
      } else {
         addStatement(format("%1% %2%[%3%];", type.getName(), s->name.name.c_str(), arrayLen));
      }

      if (type.isString()) {
         addStatement(format("%1%[0] = 0;", s->name.name.c_str()));
      }
   }
   return false;
}

bool PluginVisitor::preorder(const IR::MethodCallStatement *stat)
{
   visit(stat->methodCall);
   return false;
}

bool PluginVisitor::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "extract_re") {
         compileExtractRe(expr);
         return false;
      } else if (externMethod->method->name.name == "match") {
         compileMatch(expr);
         return false;
      } else if (externMethod->method->name.name == "strcpy") {
         compileStrcpy(expr);
         return false;
      } else if (externMethod->method->name.name == "to_number") {
         compileToNumber(expr);
         return false;
      } else if (externMethod->method->name.name == "extract") {
         compileExtract(expr);
         return false;
      } else if (externMethod->method->name.name == "advance") {
         compileAdvance(expr);
         return false;
      } else if (externMethod->method->name.name == "extract_string") {
         compileExtractString(expr);
         return false;
      } else {
         ::error("Method or function call not supported: %1%", expr);
      }
   } else {
      auto externFunc = methodInst->to<P4::ExternFunction>();
      if (externFunc != nullptr) {
         if (externFunc->method->name.name == "verify") {
            return false;
         }
      }
      ::error("Method or function call not supported: %1%", expr);
   }

   return false;
}

bool PluginVisitor::preorder(const IR::SelectExpression *s)
{
   PluginExpressionHelper ins(refMap_, typeMap_);
   if (s->select->components.size() != 1) {
      ::error("ListExpression with more than 1 expression not supported yet %1%", s);
   }
   s->select->components.at(0)->apply(ins);

   addStatement(format("switch (%1%) {", ins.getExpression()));
   increaseIndent();

   for (auto c : s->selectCases) {
      visit(c);
   }

   decreaseIndent();
   addStatement("}");

   addStatement("goto reject;");
   return false;
}

bool PluginVisitor::preorder(const IR::SelectCase *s)
{
   PluginExpressionHelper ins(refMap_, typeMap_);
   std::string dest = s->state->path->name.name.c_str();

   if (s->keyset->is<IR::DefaultExpression>()) {
      addStatement(format("default: goto %1%;", dest));
   } else {
      s->keyset->apply(ins);
      addStatement(format("case %1%: goto %2%;", ins.getExpression(), dest));
   }

   return false;
}

bool PluginVisitor::preorder(const IR::PathExpression *p)
{
   auto parent = getContext();
   if (parent != nullptr) {
      if (parent->node->is<IR::ParserState>()) {
         addStatement(format("goto %1%;", p->path->name.name.c_str()));
      }
   }
   return false;
}

void PluginVisitor::compileExtractRe(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("parse extern method requires 2 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   nlohmann::json dummy;
   LexerBuilder builder(refMap_, typeMap_, dummy);
   addStatement(format("%1%;", builder.compileCall(arg1, arg2)));
}

void PluginVisitor::compileMatch(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("match extern method requires 2 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   nlohmann::json dummy;
   LexerBuilder builder(refMap_, typeMap_, dummy);
   addStatement(format("%1%;", builder.compileCall(arg1, arg2, true)));
}

void PluginVisitor::compileStrcpy(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("strcpy extern method requires 2 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   PluginExpressionHelper ins1(refMap_, typeMap_);
   PluginExpressionHelper ins2(refMap_, typeMap_);

   arg1->apply(ins1);
   arg2->apply(ins2);

   if (!checkVarIsString(arg1) || !checkVarIsString(arg2)) {
      return;
   }

   addStatement("{");
   increaseIndent();
   addStatement("size_t i_;");
   addStatement(format("for (i_ = 0; i_ < sizeof(%1%) - 1 && %2%[i_]; i_++) {", ins1.getExpression(), ins2.getExpression()));
   increaseIndent();
   addStatement(format("%1%[i_] = %2%[i_];", ins1.getExpression(), ins2.getExpression()));
   decreaseIndent();
   addStatement("}");
   addStatement(format("%1%[i_] = 0;", ins1.getExpression()));
   decreaseIndent();
   addStatement("}");
}

void PluginVisitor::compileToNumber(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("to_number extern method requires 2 arguments: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   PluginExpressionHelper ins1(refMap_, typeMap_);
   PluginExpressionHelper ins2(refMap_, typeMap_);

   arg1->apply(ins1);
   arg2->apply(ins2);

   if (!checkVarIsString(arg1)) {
      return;
   }

   auto arg2Bits = arg2->type->to<IR::Type_Bits>();
   if (arg2Bits == nullptr) {
      ::error("expected bits type: %1%", arg2);
      return;
   }

   TypeTranslator arg2TypeHelper(arg2->type, typeMap_);
   if (arg2TypeHelper.getImplementationWidth() > 64) {
      ::error("converting string to number with more than 64 bits not supported: %1%", arg2);
      return;
   }

   if (arg2Bits->isSigned) {
      addStatement(format("%1% = strtoll((const char *) %2%, NULL, 0);", ins2.getExpression(), ins1.getExpression()));
   } else {
      addStatement(format("%1% = strtoull((const char *) %2%, NULL, 0);", ins2.getExpression(), ins1.getExpression()));
   }
}

void PluginVisitor::compileExtract(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 1) {
      ::error("expected 1 argument: %1%", expr);
      return;
   }

   auto argExpr = expr->arguments->at(0)->expression;
   auto type = typeMap_->getType(argExpr);

   auto headerType = type->to<IR::Type_Header>();
   unsigned offset_bits = 0;
   if (headerType == nullptr) {
      TypeTranslator tmp(type, typeMap_);

      addStatement(format("if (payload + %1% > payload_end) { goto reject; }", tmp.getWidth() / 8));
      compileExtractField(argExpr, tmp, "", 0, offset_bits);
      offset_bits = tmp.getWidth();
   } else {
      TypeTranslator headerHelper(headerType, typeMap_);
      addStatement(format("if (payload + %1% > payload_end) { goto reject; }", headerHelper.getWidth() / 8));

      unsigned alignment = 0;
      for (auto field : headerType->fields) {
         auto fieldType = typeMap_->getType(field);
         TypeTranslator tmp(fieldType, typeMap_);

         compileExtractField(argExpr, tmp, field->name.name.c_str(), alignment, offset_bits);
         alignment += tmp.getWidth();
         offset_bits += tmp.getWidth();
         alignment %= 8;

         PluginExpressionHelper ins(refMap_, typeMap_);
         argExpr->apply(ins);
         std::string path = format("%1%.%2%", ins.getExpression(), field->name.name.c_str());

         addDebugParserField(container_, tmp, path);
      }
   }

   if (offset_bits % 8) {
      ::error("extracted types must be aligned to 8 bits: %1%", argExpr);
      return;
   }
   addStatement(format("payload += %1%;", offset_bits / 8));
}

void PluginVisitor::compileAdvance(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 1) {
      ::error("expected 1 argument: %1%", expr);
      return;
   }

   auto arg = expr->arguments->at(0);
   PluginExpressionHelper ins(refMap_, typeMap_);
   arg->apply(ins);

   addStatement(format("payload += %1%;", ins.getExpression()));
}

void PluginVisitor::compileExtractString(const IR::MethodCallExpression *expr)
{
   if (expr->arguments->size() != 2) {
      ::error("expected 2 argument: %1%", expr);
      return;
   }

   auto arg1 = expr->arguments->at(0)->expression;
   auto arg2 = expr->arguments->at(1)->expression;

   PluginExpressionHelper ins1(refMap_, typeMap_);
   PluginExpressionHelper ins2(refMap_, typeMap_);

   arg1->apply(ins1);
   arg2->apply(ins2);

   if (!checkVarIsString(arg1)) {
      return;
   }

   addStatement(format("if (payload + %1% > payload_end) { goto reject; }", ins2.getExpression()));

   addStatement("{");
   increaseIndent();
   addStatement("size_t i_;");
   addStatement(format("for (i_ = 0; i_ < sizeof(%1%) - 1 && i_ < %2%; i_++) {", ins1.getExpression(), ins2.getExpression()));
   increaseIndent();
   addStatement(format("%1%[i_] = payload[i_];", ins1.getExpression()));
   decreaseIndent();
   addStatement("}");
   addStatement(format("%1%[i_] = 0;", ins1.getExpression()));
   decreaseIndent();
   addStatement("}");

   addStatement(format("payload += %1%;", ins2.getExpression()));
}

void PluginVisitor::compileExtractField(const IR::Expression *expr, TypeTranslator &type, std::string fieldName, unsigned alignment, unsigned offset_bits)
{
   uint32_t toLoad;
   uint32_t width = type.getWidth();
   uint32_t shiftBits;

   PluginExpressionHelper ins(refMap_, typeMap_);
   expr->apply(ins);

   std::string path = format("%1%.%2%", ins.getExpression(), fieldName);
   std::string loaderFunc = "";
   std::string transformFunc = "";
   std::string code = "";
   std::string mask = "";

   if (fieldName == "") {
      path = format("%1%", ins.getExpression());
   }

   if (width <= 64) {
      getLoadParameters(width + alignment, loaderFunc, transformFunc, toLoad);
      shiftBits = toLoad - (width + alignment);

      if (width != toLoad) {
         mask = format(" & FPP_MASK(%1%, %2%)", type.getName(), width);
      }
      if (shiftBits != 0) {
         if (toLoad <= 64) {
            code = format("%1% = (%2%)(%3%(%4%(payload, %5%)) >> %6%)%7%;",
               path, type.getName(), transformFunc, loaderFunc, offset_bits / 8, shiftBits, mask);
         } else {
            // This code is used when bits to load are > 64 (width + alignment > 64).
            // This means we have to load 64 bits and 8 additional bits and put it together.

            // Load 64 bits
            std::string part1 = format("(%1%((%2%)(%3%(payload, %4%))) << %5%)%6%",
               transformFunc, type.getName(), loaderFunc, offset_bits / 8, 8 - shiftBits, mask);

            // Load 8 bits
            std::string part2 = format("((uint8_t)(load_byte(payload, %1%) >> %2%) & FPP_MASK(uint8_t, %3%))",
               (offset_bits + width) / 8, shiftBits, 8 - shiftBits);

            code = format("%1% = (%2%)(%3%) | (%2%)(%4%);", path, type.getName(), part1, part2);
         }
      } else {
         code = format("%1% = %2%((%3%)(%4%(payload, %5%)))%6%;",
         path, transformFunc, type.getName(), loaderFunc, offset_bits / 8, mask);
      }

      addStatement(code);
   } else {
      loaderFunc = "load_byte";
      unsigned loadWidth = 8;
      unsigned bytes = width / 8 + (width % 8 ? 1 : 0);
      shiftBits = 0;

      if (alignment != 0) {
         loaderFunc = "load_half";
         loadWidth = 16;
         shiftBits = 8 - alignment;
      }

      for (unsigned i = 0; i < bytes; i++) {
         if ((i == bytes - 1) && width % 8) {
            code = format("%1%[%2%] = (uint8_t)((%3%(payload, %4%) >> %5%) & FPP_MASK(uint8_t, %7%));",
               path, i, loaderFunc, (offset_bits + i * loadWidth) / 8, shiftBits, width % 8);
         } else {
            code = format("%1%[%2%] = (uint8_t)(%3%(payload, %4%) >> %5%);",
               path, i, loaderFunc, (offset_bits + i * loadWidth) / 8, shiftBits);
         }
         addStatement(code);
      }
   }
}

bool PluginVisitor::checkVarIsString(const IR::Expression *expr)
{
   auto pathExpr = expr->to<IR::PathExpression>();

   if (pathExpr == nullptr && expr->is<IR::Member>()) {
      auto member = expr->to<IR::Member>();
      auto type = typeMap_->getType(member->expr);
      if (type->is<IR::Type_StructLike>()) {
         auto structDef = type->to<IR::Type_StructLike>();
         for (auto f : structDef->fields) {
            if (f->name == member->member.name) {
               auto annot = f->getAnnotation(ANNOTATION_STRING);
               if (annot == nullptr) {
                  ::error("expected string: %1%", expr);
                  return false;
               }
               break;
            }
         }
      } else {
         BUG("expected struct like node %1%", type);
      }
   } else if (pathExpr != nullptr) {
      auto decl = refMap_->getDeclaration(pathExpr->path);
      auto annot = decl->getAnnotation(ANNOTATION_STRING);
      if (annot == nullptr) {
         ::error("expected string: %1%", expr);
         return false;
      }
   } else {
      ::error("expected string: %1%", expr);
      return false;
   }

   return true;
}


//
// PluginGenerator
//


PluginGenerator::PluginGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : Generator(options, topLevel, refMap, typeMap)
{
}

void PluginGenerator::generate()
{
   nlohmann::json templatesContainer;
   nlohmann::json fillContainer;

   auto main = topLevel_->getMain();
   if (main == nullptr) {
      ::error("Package main not found");
      return;
   }
   auto plugins = main->getParameterValue("plugins")->to<IR::PackageBlock>();
   if (plugins == nullptr) {
      ::error("No plugins package found");
      return;
   }

   for (auto plugin : plugins->getConstructorParameters()->parameters) {
      auto plug = plugins->getParameterValue(plugin->toString());
      compiledPluginName = plugin->toString();
      compilePlugin(plug->to<const IR::PackageBlock>());
      if (errorCount() > 0) {
         return;
      }
   }

   if (!checkTemplateFile(options_.templatesDir_ + "/plugin.c.tmplt") ||
       !checkTemplateFile(options_.templatesDir_ + "/plugin.h.tmplt") ||
       !checkTemplateFile(options_.templatesDir_ + "/regex.c.re.tmplt") ||
       !checkTemplateFile(options_.templatesDir_ + "/regex.h.tmplt")) {
      return;
   }

   // Create files.
   inja::Environment env = inja::Environment(options_.templatesDir_ + "/", options_.genDir_ + "/");
   inja::Template tmpltPluginSource = env.parse_template("plugin.c.tmplt");
   env.write(tmpltPluginSource, plugin_, "plugin.c");

   inja::Template tmpltPluginHeader = env.parse_template("plugin.h.tmplt");
   env.write(tmpltPluginHeader, plugin_, "plugin.h");

   inja::Template tmpltRegexSource = env.parse_template("regex.c.re.tmplt");
   env.write(tmpltRegexSource, plugin_, "regex.c.re");

   inja::Template tmpltRegexHeader = env.parse_template("regex.h.tmplt");
   env.write(tmpltRegexHeader, plugin_, "regex.h");
}

void PluginGenerator::compilePlugin(const IR::PackageBlock *plugin)
{
   if (plugin == nullptr) {
      ::error("failed to get plugin as PackageBlock node");
      return;
   }

   auto create = plugin->getParameterValue("create");
   auto update = plugin->getParameterValue("update");

   if (create == nullptr || update == nullptr) {
      ::error("unable to get create or update parameter from %1% plugin", plugin->toString());
      return;
   }

   nlohmann::json pluginContainer;
   if (create->is<IR::ParserBlock>()) {
      auto createBlock = create->to<IR::ParserBlock>()->container;
      nlohmann::json code;

      for (auto param : createBlock->getApplyParameters()->parameters) {
         if (param->toString() == "ext") {
            TypeTranslator type(param->type, typeMap_);
            pluginContainer["type"] = type.getName();
         }
      }

      PluginVisitor ins(refMap_, typeMap_, code);
      createBlock->apply(ins);

      if (errorCount() > 0) {
         return;
      }

      LexerHelper helper(refMap_, typeMap_, pluginContainer);
      createBlock->apply(helper);

      pluginContainer["create"] = code;
   } else {
      ::error("only parser block is supported when specifying create or update");
   }

   if (update->is<IR::ParserBlock>()) {
      auto updateBlock = update->to<IR::ParserBlock>()->container;
      nlohmann::json code;

      for (auto param : updateBlock->getApplyParameters()->parameters) {
         if (param->toString() == "ext") {
            TypeTranslator type(param->type, typeMap_);
            pluginContainer["type"] = type.getName();
         }
      }

      PluginVisitor ins(refMap_, typeMap_, code);
      updateBlock->apply(ins);

      if (errorCount() > 0) {
         return;
      }

      LexerHelper helper(refMap_, typeMap_, pluginContainer);
      updateBlock->apply(helper);

      pluginContainer["update"] = code;
   } else {
      ::error("only parser block is supported when specifying create or update");
   }

   pluginContainer["name"] = compiledPluginName;
   plugin_["plugins"] += pluginContainer;
}

} // namespace exporter
