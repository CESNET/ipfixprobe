/**
 * \file cache.cpp
 * \brief Contains cache code generation objects. Compiles cache extern P4 block.
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

#include "cache.h"

namespace exporter {

//
// CacheExpressionHelper
//


CacheExpressionHelper::CacheExpressionHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : ConstructExpression(refMap, typeMap), headersFound_(false), flowFound_(false)
{
   setName("CacheExpressionHelper");
}

bool CacheExpressionHelper::preorder(const IR::Member *expr)
{
   visit(expr->expr);
   if (headersFound_) {
      auto type = typeMap_->getType(expr);
      if (type == nullptr || !type->is<IR::Type_Header>()) {
         BUG("unexpected nonheader type in headers struct");
      }

      TypeTranslator tmp(type->to<IR::Type_Header>(), typeMap_);
      expression_ += format("((%1% *) hdr->data)[0]", tmp.getName());
      headersFound_ = false;
   } else {
      expression_ += ".";
      expression_ += expr->member.name.c_str();
   }
   return false;
}

bool CacheExpressionHelper::preorder(const IR::PathExpression *expr)
{
   std::string path = expr->path->name.name.c_str();

   if (path == "headers") {
      headersFound_ = true;
   } else if (path == "flow") {
      flowFound_ = true;
      expression_ +=  path + "[0]";
   } else {
      expression_ += path;
   }
   return false;
}

bool CacheExpressionHelper::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "is_present") {
         processPresent(expr->arguments);
         return false;
      } else if (externMethod->method->name.name == "is_next") {
         processNext(expr->arguments);
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

void CacheExpressionHelper::processPresent(const IR::Vector<IR::Argument> *args)
{
   if (!checkCacheMethods(args)) {
      return;
   }
   auto arg = args->at(0);

   TypeTranslator type(arg->expression->type, typeMap_);
   expression_ += format("(hdr->type == %1%)", type.getNameShort());
}

void CacheExpressionHelper::processNext(const IR::Vector<IR::Argument> *args)
{
   if (!checkCacheMethods(args)) {
      return;
   }
   auto arg = args->at(0);

   TypeTranslator type(arg->expression->type, typeMap_);
   expression_ += format("(hdr->next != NULL ? hdr->next->type == %1% : 0)", type.getNameShort());
}

bool CacheExpressionHelper::checkCacheMethods(const IR::Vector<IR::Argument> *args)
{
   if (args->size() != 1) {
      ::error("cache extern block methods must contain one argument");
      return false;
   }

   auto arg = args->at(0);
   if (!arg->expression->type->is<IR::Type_Header>()) {
      ::error("cache extern block methods must contain type header as an argument");
      return false;
   }

   auto member = arg->expression->to<IR::Member>();
   if (member == nullptr) {
      ::error("is_present and is_next methods only accept members from headers_s struct: %1%", arg);
      return false;
   }

   auto pathExpr = member->expr->to<IR::PathExpression>();
   if (pathExpr == nullptr) {
      ::error("is_present and is_next methods only accept members from headers_s struct: %1%", arg);
      return false;
   }

   std::string path = pathExpr->path->name.name.c_str();
   if (path != "headers") {
      ::error("is_present and is_next methods only accept members from headers_s struct: %1%", arg);
      return false;
   }
   return true;
}


//
// CacheVisitor
//


CacheVisitor::CacheVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container)
   : CodeBuilder(refMap, typeMap, container)
{
   setName("CacheVisitor");
}

bool CacheVisitor::preorder(const IR::Declaration *s)
{
   (void) s;
   return false;
}

bool CacheVisitor::preorder(const IR::BlockStatement *s)
{
   visit(s->components);
   return false;
}

bool CacheVisitor::preorder(const IR::AssignmentStatement *s)
{
   CacheExpressionHelper left(refMap_, typeMap_);
   CacheExpressionHelper right(refMap_, typeMap_);
   s->left->apply(left);
   s->right->apply(right);

   auto type = typeMap_->getType(s->right);
   if (type != nullptr && type->is<IR::Type_Bits>()) {
      TypeTranslator tmp(type, typeMap_);
      if (tmp.getWidth() <= 64) {
         addStatement(format("%1% = %2%;", left.getExpression(), right.getExpression()));
      } else {
         int width = tmp.getImplementationWidth() / 8;
         addStatement(format("memcpy(%1%, %2%, %3%);", left.getExpression(), right.getExpression(), width));
      }
   } else {
      addStatement(format("%1% = %2%;", left.getExpression(), right.getExpression()));
   }

   return false;
}

bool CacheVisitor::preorder(const IR::IfStatement *s)
{
   CacheExpressionHelper ins(refMap_, typeMap_);
   s->condition->apply(ins);

   addStatement(format("if (%1%) {", ins.getExpression()));
   increaseIndent();
   visit(s->ifTrue);
   decreaseIndent();
   if (s->ifFalse != nullptr) {
      addStatement(format("} else {"));
      increaseIndent();
      visit(s->ifFalse);
      decreaseIndent();
   }
   addStatement("}");
   return false;
}


//
// CacheCreateVisitor
//


CacheCreateVisitor::CacheCreateVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container)
   : CacheVisitor(refMap, typeMap, container)
{
   setName("CacheCreateVisitor");
}

bool CacheCreateVisitor::preorder(const IR::MethodCallStatement *s)
{
   (void) s;
   visit(s->methodCall);
   return false;
}

bool CacheCreateVisitor::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "add_to_key") {
         processAddToKey(expr->arguments);
         return false;
      } else if (externMethod->method->name.name != "register_conflicting_headers") {
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

void CacheCreateVisitor::setSplitStatement(const std::string &cond)
{
   addStatement(format("if (headers[hdr->type] || %1%) {", cond));
   increaseIndent();
   addStatement("*next_flow = hdr;");
   addStatement("return success;");
   decreaseIndent();
   addStatement("}");
   addStatement("headers[hdr->type] = 1;");
}

void CacheCreateVisitor::processAddToKey(const IR::Vector<IR::Argument> *args)
{
   if (args->size() != 1) {
      ::error("cache extern block methods must contain one argument");
      return;
   }

   auto arg = args->at(0);
   if (!arg->expression->type->is<IR::Type_Bits>()) {
      ::error("cache add_to_key method must contain type bits as an argument");
      return;
   }

   TypeTranslator type(arg->expression->type->to<IR::Type_Bits>(), typeMap_);
   CacheExpressionHelper ins(refMap_, typeMap_);
   arg->expression->apply(ins);

   if (type.getWidth() <= 64) {
      addStatement(format("*(%1% *)(key + *key_len) = %2%;", type.getName(), ins.getExpression()));
      addStatement(format("*key_len += %1%;", type.getImplementationWidth() / 8));
   } else {
      int width = type.getImplementationWidth() / 8;
      addStatement(format("memcpy((key + *key_len), %1%, %2%);", ins.getExpression(), width));
      addStatement(format("*key_len += %1%;", width));
   }
}


//
// CacheUpdateVisitor
//


CacheUpdateVisitor::CacheUpdateVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container)
   : CacheVisitor(refMap, typeMap, container)
{
   setName("CacheUpdateVisitor");
}

bool CacheUpdateVisitor::preorder(const IR::MethodCallStatement *s)
{
   (void) s;
   visit(s->methodCall);
   return false;
}

bool CacheUpdateVisitor::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name != "register_conflicting_headers") {
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

void CacheUpdateVisitor::setSplitStatement(const std::string &cond)
{
   addStatement(format("if (headers[hdr->type] || %1%) {", cond));
   increaseIndent();
   addStatement("return;");
   decreaseIndent();
   addStatement("}");
   addStatement("headers[hdr->type] = 1;");
}


//
// ConflictingTypesHelper
//


ConflictingTypesHelper::ConflictingTypesHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : refMap_(refMap), typeMap_(typeMap)
{
   setName("ConflictingTypesHelper");
}

bool ConflictingTypesHelper::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "register_conflicting_headers") {
         if (expr->arguments->size() != 2) {
            ::error("register_conflicting_headers method requires 2 arguments");
            return false;
         }
         auto arg1 = expr->arguments->at(0);
         auto arg2 = expr->arguments->at(1);
         TypeTranslator type1(arg1->expression->type, typeMap_);
         TypeTranslator type2(arg2->expression->type, typeMap_);
         // TODO: better code
         std::string code = format("((hdr->type == %1% && headers[%2%]) || (hdr->type == %2% && headers[%1%]))",
            type1.getNameShort(), type2.getNameShort());

         if (cond_ == "") {
            cond_ = code;
         } else {
            cond_ += format(" || %1%", code);
         }
      }
   }
   return false;
}


std::string ConflictingTypesHelper::getCond() const
{
   return cond_;
}


//
// ComputeKeyWidthHelper
//


ComputeKeyWidthHelper::ComputeKeyWidthHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap) : refMap_(refMap), typeMap_(typeMap), width_(0)
{
   setName("ComputeKeyWidthHelper");
}

bool ComputeKeyWidthHelper::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "add_to_key") {
         if (expr->arguments->size() == 1) {
            auto arg = expr->arguments->at(0);
            TypeTranslator type(arg->expression->type, typeMap_);
            width_ += type.getImplementationWidth();
         }
      }
   }
   return false;
}

uint32_t ComputeKeyWidthHelper::getWidth() const
{
   return width_;
}


//
// CacheGenerator
//


CacheGenerator::CacheGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : Generator(options, topLevel, refMap, typeMap)
{
}

void CacheGenerator::compileCreateBlock(const IR::ControlBlock *block, nlohmann::json &container)
{
   ConflictingTypesHelper splitCondHelper(refMap_, typeMap_);
   block->apply(splitCondHelper);

   // Compile statements.
   CacheCreateVisitor ins(refMap_, typeMap_, container);
   ins.setSplitStatement(splitCondHelper.getCond());
   block->container->apply(ins);

   // Compile local variables.
   for (auto decl : block->container->controlLocals) {
      auto tmpDecl = dynamic_cast<const IR::Declaration_Variable *>(decl);
      nlohmann::json tmp;
      TypeTranslator type(tmpDecl->type, typeMap_);

      type.fillJson(tmp);
      tmp["name"] = decl->name.name;
      container["local_variables"] += tmp;
   }
}

void CacheGenerator::compileUpdateBlock(const IR::ControlBlock *block, nlohmann::json &container)
{
   ConflictingTypesHelper splitCondHelper(refMap_, typeMap_);
   block->apply(splitCondHelper);

   // Compile statements.
   CacheUpdateVisitor ins(refMap_, typeMap_, container);
   ins.setSplitStatement(splitCondHelper.getCond());
   block->container->apply(ins);

   // Compile local variables.
   for (auto decl : block->container->controlLocals) {
      auto tmpDecl = dynamic_cast<const IR::Declaration_Variable *>(decl);
      nlohmann::json tmp;
      TypeTranslator type(tmpDecl->type, typeMap_);

      type.fillJson(tmp);
      tmp["name"] = decl->name.name;
      container["local_variables"] += tmp;
   }
}

void CacheGenerator::generate()
{
   nlohmann::json createContainer;
   nlohmann::json updateContainer;

   auto main = topLevel_->getMain();
   if (main == nullptr) {
      ::error("Package main not found");
      return;
   }
   auto createBlock = main->getParameterValue("create")->to<IR::ControlBlock>();
   if (createBlock == nullptr) {
      ::error("No flow cache create block found");
      return;
   }
   auto updateBlock = main->getParameterValue("update")->to<IR::ControlBlock>();
   if (updateBlock == nullptr) {
      ::error("No flow cache update block found");
      return;
   }

   // Compile create and update control blocks.
   compileCreateBlock(createBlock, createContainer);
   compileUpdateBlock(updateBlock, updateContainer);

   cache_["flow_create"] = createContainer;
   cache_["flow_update"] = updateContainer;

   // Compile key width.
   ComputeKeyWidthHelper widthIns(refMap_, typeMap_);
   createBlock->container->apply(widthIns);
   cache_["key_width"] = widthIns.getWidth() / 8;

   for (auto obj : topLevel_->getProgram()->objects) {
      if (obj->is<IR::Type_Struct>() || obj->is<IR::Type_Header>() || obj->is<IR::Type_HeaderUnion>()) {
         auto tmp = obj->to<IR::Type_StructLike>();

         if (tmp->name.name == "headers_s") {
            cache_["header_cnt"] = tmp->fields.size();
            break;
         }
      }
   }

   if (errorCount() > 0) {
      return;
   }

   if (!checkTemplateFile(options_.templatesDir_ + "/cache.c.tmplt") ||
       !checkTemplateFile(options_.templatesDir_ + "/cache.h.tmplt") ||
       !checkTemplateFile(options_.templatesDir_ + "/xxhash.c.tmplt") ||
       !checkTemplateFile(options_.templatesDir_ + "/xxhash.h.tmplt")) {
      return;
   }

   // Create files.
   inja::Environment env = inja::Environment(options_.templatesDir_ + "/", options_.genDir_ + "/");
   inja::Template tmpltSource = env.parse_template("cache.c.tmplt");
   env.write(tmpltSource, cache_, "cache.c");

   inja::Template tmpltHeader = env.parse_template("cache.h.tmplt");
   env.write(tmpltHeader, cache_, "cache.h");

   // Create other files needed for cache.c
   inja::Template tmpltHashSource = env.parse_template("xxhash.c.tmplt");
   env.write(tmpltHashSource, cache_, "xxhash.c");

   inja::Template tmpltHashHeader = env.parse_template("xxhash.h.tmplt");
   env.write(tmpltHashHeader, cache_, "xxhash.h");
}

} // namespace exporter
