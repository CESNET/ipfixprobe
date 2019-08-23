/**
 * \file exporter.cpp
 * \brief Contains exporter code generation objects. Compiles exporter extern P4 block.
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

#include "exporter.h"

namespace exporter {

//
// ExporterExpressionHelper
//

ExporterExpressionHelper::ExporterExpressionHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : ConstructExpression(refMap, typeMap)
{
   setName("ExporterExpressionHelper");
}

bool ExporterExpressionHelper::preorder(const IR::Member *expr)
{
   visit(expr->expr);
   expression_ += ".";
   expression_ += expr->member.name.c_str();
   return false;
}

bool ExporterExpressionHelper::preorder(const IR::PathExpression *expr)
{
   std::string path = expr->path->name.name.c_str();

   if (path == "flow" || path == "ext") {
      expression_ +=  path + "[0]";
   } else {
      expression_ += path;
   }
   return false;
}


//
// ExporterInitVisitor
//


ExporterInitVisitor::ExporterInitVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container)
   : CodeBuilder(refMap, typeMap, container)
{
   setName("ExporterInitVisitor");
}

bool ExporterInitVisitor::preorder(const IR::MethodCallStatement *s)
{
   (void) s;
   visit(s->methodCall);
   return false;
}

bool ExporterInitVisitor::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "register_template") {
         processRegisterTemplate(expr->arguments);
         return false;
      } else if (externMethod->method->name.name == "add_template_field") {
         processAddTemplateField(expr->arguments);
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

bool ExporterInitVisitor::preorder(const IR::BlockStatement *s)
{
   visit(s->components);

   auto context = getContext();
   if (context != nullptr && context->parent != nullptr && !context->parent->node->is<IR::ControlBlock>()) {
      return false;
   }

   if (::errorCount() > 0) {
      return false;
   }

   // Process all templates and fields.
   for (unsigned i = 0; i < templateMapping_.size(); i++) {
      std::string structInit = "(const template_file_record_t *[]){ ";
      auto fields = templateFields_[i];
      for (unsigned j = 0; j < fields.size(); j++) {
         auto field = fields[j];
         structInit += format("&(template_file_record_t){ %1%, %2%, %3% }, ", field.enterpriseNumber_, field.elementID_, field.length_);
      }
      structInit += "NULL }";

      addStatement(format("ipfix->templateArray[%1%] = ipfix_create_template(ipfix, %2%);", i, structInit));
   }

   return false;
}

std::vector<int> ExporterInitVisitor::getTemplateMapping() const
{
   return templateMapping_;
}

std::vector<std::vector<template_field_t>> ExporterInitVisitor::getTemplateFields() const
{
   return templateFields_;
}

void ExporterInitVisitor::processRegisterTemplate(const IR::Vector<IR::Argument> *args)
{
   if (args->size() != 1) {
      ::error("exporter register template method must contain one argument");
      return;
   }
   auto arg = args->at(0)->to<IR::Argument>();
   auto type = arg->expression->to<IR::Constant>();
   if (type == nullptr) {
      ::error("invalid type for register template method: %1%", arg->expression);
      return;
   }

   int value = type->asInt();
   if (value < 0 || value > 255 || !type->fitsInt()) {
      ::error("invalid value for register template method (use values 0-255)");
      return;
   }

   for (unsigned i = 0; i < templateMapping_.size(); i++) {
      if (templateMapping_[i] == value) {
         ::error("invalid value for register template method (value %1% already used for template registration)", value);
         return;
      }
   }

   templateMapping_.push_back(value);
   templateFields_.push_back(std::vector<template_field_t>());
   size_t templateIndex = templateFields_.size() - 1;

   templateFields_[templateIndex].push_back({0, 10, 2}); // Input interface
   templateFields_[templateIndex].push_back({0, 152, 8}); // First time
   templateFields_[templateIndex].push_back({0, 153, 8}); // Last time
   templateFields_[templateIndex].push_back({8057, 10000, 8}); // ID
   templateFields_[templateIndex].push_back({8057, 10001, 8}); // Parent ID
}

void ExporterInitVisitor::processAddTemplateField(const IR::Vector<IR::Argument> *args)
{
   if (args->size() != 3) {
      ::error("exporter add template field method must contain 3 arguments");
      return;
   }

   auto first = args->at(0)->to<IR::Argument>()->expression->to<IR::Constant>();
   auto second = args->at(1)->to<IR::Argument>()->expression->to<IR::Constant>();
   auto third = args->at(2)->to<IR::Argument>()->expression->to<IR::Constant>();

   if (first == nullptr || second == nullptr || third == nullptr) {
      ::error("invalid value for register template field (use values 0-65536)");
      return;
   }

   int en = first->asInt();
   int id = second->asInt();
   int len = third->asInt();

   if (en < 0 || en > 65535 || !first->fitsInt() ||
      id < 0 || id > 65535 || !second->fitsInt()) {
      ::error("invalid value for register template field (use values 0-65536 for first and second argument)");
      return;
   }
   if (len < -1 || len == 0 || len > 65535 || !third->fitsInt()) {
      ::error("invalid value for registering template field (use values 1-65536 or -1 for third argument)");
      return;
   }

   if (len == 0) {
      ::error("IPFIX field cannot have zero length size: %1%", third);
      return;
   }

   if (templateMapping_.size() == 0) {
      ::error("invalid use of template field registration (register template before adding fields): %1%", args);
      return;
   }

   templateFields_[templateFields_.size() - 1].push_back({(uint16_t) en, (uint16_t) id, len});
}


//
// ExporterFillVisitor
//


ExporterFillVisitor::ExporterFillVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container,
      std::vector<int> templateMapping, std::vector<std::vector<template_field_t>> templateFields)
   : CodeBuilder(refMap, typeMap, container), templateMapping_(templateMapping), templateFields_(templateFields)
{
   setName("ExporterFillVisitor");

   for (unsigned i = 0; i < templateMapping_.size(); i++) {
      auto fields = templateFields_[i];
      int size = 0;
      for (unsigned j = 0; j < fields.size(); j++) {
         if (fields[j].length_ > 0) {
            size += fields[j].length_;
         } else {
            size += 1;
         }
      }
      templateSize_.push_back(size);
   }

   currentTemplate_ = -1;
   currentTemplateField_ = -1;
   currentFillSize_ = -1;
}

bool ExporterFillVisitor::preorder(const IR::MethodCallStatement *s)
{
   (void) s;
   visit(s->methodCall);
   return false;
}

bool ExporterFillVisitor::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "set_template") {
         processSetTemplate(expr->arguments);
         return false;
      } else if (externMethod->method->name.name == "add_field") {
         processAddField(expr->arguments);
         return false;
      } else if (externMethod->method->name.name == "add_field_empty") {
         addStatement("*buffer = 0;");
         addStatement("buffer++;");
      } else if (externMethod->method->name.name == "set_finish") {
         addStatement(format("tmplt->bufferSize = bufferSize;"));
         addStatement(format("tmplt->recordCount++;"));
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

bool ExporterFillVisitor::preorder(const IR::BlockStatement *s)
{
   visit(s->components);
   return false;
}

bool ExporterFillVisitor::preorder(const IR::AssignmentStatement *s)
{
   ExporterExpressionHelper left(refMap_, typeMap_);
   ExporterExpressionHelper right(refMap_, typeMap_);
   s->left->apply(left);
   s->right->apply(right);

   auto type = typeMap_->getType(s->right);
   if (type != nullptr && type->is<IR::Type_Bits>()) {
      TypeTranslator typeTranslated(type, typeMap_);
      if (typeTranslated.getWidth() <= 64) {
         addStatement(format("%1% = %2%;", left.getExpression(), right.getExpression()));
      } else {
         int width = typeTranslated.getImplementationWidth() / 8;
         addStatement(format("memcpy(%1%, %2%, %3%);", left.getExpression(), right.getExpression(), width));
      }
   } else {
      addStatement(format("%1% = %2%;", left.getExpression(), right.getExpression()));
   }

   return false;
}

bool ExporterFillVisitor::preorder(const IR::IfStatement *s)
{
   ExporterExpressionHelper exprIns(refMap_, typeMap_);
   s->condition->apply(exprIns);

   addStatement(format("if (%1%) {", exprIns.getExpression()));
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

void ExporterFillVisitor::processSetTemplate(const IR::Vector<IR::Argument> *args)
{
   if (args->size() != 1) {
      ::error("exporter set template method must contain one argument");
      return;
   }
   auto arg = args->at(0)->to<IR::Argument>();
   auto type = arg->expression->to<IR::Constant>();
   if (type == nullptr) {
      ::error("invalid type for set template method: %1%", arg->expression);
      return;
   }

   int value = type->asInt();
   if (value < 0 || value > 255 || !type->fitsInt()) {
      ::error("invalid value for set template method (use values 0-255)");
      return;
   }

   int templateIndex = -1;
   for (unsigned i = 0; i < templateMapping_.size(); i++) {
      if (templateMapping_[i] == value) {
         templateIndex = i;
      }
   }
   if (templateIndex < 0) {
      ::error("invalid value for set template method (no template with value %1% found)", value);
      return;
   }

// TODO:
/*
   if (currentTemplate_ >= 0 && templateSize_[templateIndex] != currentFillSize_) {
      ::error("last template %1% was not correctly filled (filled %2% out of %3% bytes)",
            templateMapping_[templateIndex], currentFillSize_, templateSize_[templateIndex]);
      return;
   }*/

   currentTemplate_ = templateIndex;
   currentFillSize_ = 0;
   currentTemplateField_ = 0;

   addStatement(format("tmplt = ipfix->templateArray[%1%];", templateIndex));
   addStatement(format("while (tmplt->bufferSize + %1% > TEMPLATE_BUFFER_SIZE) {", templateSize_[templateIndex]));
   increaseIndent();
   addStatement(format("ipfix_send_templates(ipfix);"));
   addStatement(format("ipfix_send_data(ipfix);"));
   decreaseIndent();
   addStatement(format("}"));
   addStatement(format("buffer = tmplt->buffer + tmplt->bufferSize;"));
   addStatement(format("bufferSize = tmplt->bufferSize + %1%;", templateSize_[templateIndex]));

   // Fill direction, first and last timeout fields.
   addStatement(format("*(uint16_t *) buffer = ntohs(ipfix->dir_bit_field);"));
   addStatement(format("buffer += 2;"));
   currentFillSize_ += 2;
   currentTemplateField_++;
   addStatement(format("*(uint64_t *) buffer = ntohll((uint64_t) flow->first.tv_sec * 1000 + flow->first.tv_usec / 1000);"));
   addStatement(format("buffer += 8;"));
   currentFillSize_ += 8;
   currentTemplateField_++;
   addStatement(format("*(uint64_t *) buffer = ntohll((uint64_t) flow->last.tv_sec * 1000 + flow->last.tv_usec / 1000);"));
   addStatement(format("buffer += 8;"));
   currentFillSize_ += 8;
   currentTemplateField_++;
   addStatement(format("*(uint64_t *) buffer = ntohll(flow->id);"));
   addStatement(format("buffer += 8;"));
   currentFillSize_ += 8;
   currentTemplateField_++;
   addStatement(format("*(uint64_t *) buffer = ntohll(flow->parent);"));
   addStatement(format("buffer += 8;"));
   currentFillSize_ += 8;
   currentTemplateField_++;
}

void ExporterFillVisitor::processAddField(const IR::Vector<IR::Argument> *args)
{
   if (args->size() != 1) {
      ::error("exporter add field method must contain one argument");
      return;
   }
   auto arg = args->at(0)->to<IR::Argument>();

   ExporterExpressionHelper exprIns(refMap_, typeMap_);
   arg->expression->apply(exprIns);

   auto exprType = typeMap_->getType(arg->expression);
   TypeTranslator typeTranslated(exprType, typeMap_);
   int width = typeTranslated.getWidth();

   // TODO: check if template is set
   // TODO: check fields length
   if (varIsString(arg->expression)) {
      addStatement(format("str_len = strlen((const char *) %1%);", exprIns.getExpression()));
      addStatement("if (bufferSize + str_len > TEMPLATE_BUFFER_SIZE) {");
      increaseIndent();
      addStatement(format("while (bufferSize + str_len > TEMPLATE_BUFFER_SIZE) {"));
      increaseIndent();
      addStatement(format("ipfix_send_templates(ipfix);"));
      addStatement(format("ipfix_send_data(ipfix);"));
      addStatement("bufferSize = tmplt->bufferSize;");
      decreaseIndent();
      addStatement(format("}"));
      addStatement(format("continue;"));
      decreaseIndent();
      addStatement("}");
      addStatement("*buffer = str_len;");
      addStatement("buffer += 1;");
      addStatement(format("memcpy(buffer, %1%, str_len);", exprIns.getExpression()));
      addStatement("bufferSize += str_len;");
      addStatement("buffer += str_len;");
   } else if (width <= 16 || width == 32 || width == 64) {
      const char *func = "";
      if (width <= 8) {
         func = "";
      } else if (width <= 16) {
         func = "ntohs";
      } else if (width <= 32) {
         func = "ntohl";
      } else if (width == 64) {
         func = "ntohll";
      }
      addStatement(format("*(%1% *) buffer = %2%(%3%);", typeTranslated.getName(), func, exprIns.getExpression()));
      addStatement(format("buffer += %1%;", width / 8));
   } else if (width < 64) {
      int bytes = (width / 8) + (width % 8 ? 1 : 0);
      for (int i = 0; i < bytes; i++) {
         addStatement(format("buffer[%1%] = (uint8_t) ((%2% >> %3%) & 0xFF);", i, exprIns.getExpression(), bytes * 8 - 8 - i * 8));
      }
      addStatement(format("buffer += %1%;", bytes));
   } else {
      width /= 8;

      addStatement(format("memcpy(buffer, %1%, %2%);", exprIns.getExpression(), width));
      addStatement(format("buffer += %1%;", width));
   }
}

bool ExporterFillVisitor::varIsString(const IR::Expression *expr)
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
                  return false;
               }
               break;
            }
         }
      }
   } else if (pathExpr != nullptr) {
      auto decl = refMap_->getDeclaration(pathExpr->path);
      auto annot = decl->getAnnotation(ANNOTATION_STRING);
      if (annot == nullptr) {
         return false;
      }
   } else {
      return false;
   }

   return true;
}


//
// TemplateCountInspector
//


TemplateCountInspector::TemplateCountInspector(P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : refMap_(refMap), typeMap_(typeMap), count_(0)
{
   setName("TemplateCountInspector");
}

bool TemplateCountInspector::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == "register_template") {
         count_++;
      }
   }
   return false;
}

uint32_t TemplateCountInspector::getCount() const
{
   return count_;
}


//
// ExporterGenerator
//


ExporterGenerator::ExporterGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : Generator(options, topLevel, refMap, typeMap)
{
}

void ExporterGenerator::generate()
{
   nlohmann::json templatesContainer;
   nlohmann::json fillContainer;

   auto main = topLevel_->getMain();
   if (main == nullptr) {
      ::error("Package main not found");
      return;
   }
   auto templatesBlock = main->getParameterValue("init")->to<IR::ControlBlock>();
   if (templatesBlock == nullptr) {
      ::error("No exporter templates block found");
      return;
   }
   auto fillBlock = main->getParameterValue("export")->to<IR::ControlBlock>();
   if (fillBlock == nullptr) {
      ::error("No exporter fill flow block found");
      return;
   }

   // Compile init and fill control blocks.
   ExporterInitVisitor insInit(refMap_, typeMap_, templatesContainer);
   templatesBlock->apply(insInit);

   ExporterFillVisitor insFill(refMap_, typeMap_, fillContainer, insInit.getTemplateMapping(), insInit.getTemplateFields());
   fillBlock->apply(insFill);

   auto plugins = main->getParameterValue("plugins")->to<IR::PackageBlock>();
   if (plugins == nullptr) {
      ::error("No plugins package found");
      return;
   }

   nlohmann::json extensions;
   for (auto plugin : plugins->getConstructorParameters()->parameters) {
      auto plug = plugins->getParameterValue(plugin->toString());
      auto pluginPackage = plug->to<IR::PackageBlock>();
      auto pluginExport = pluginPackage->getParameterValue("export");
      if (pluginExport == nullptr) {
         continue;
      }
      auto pluginBlock = pluginExport->to<IR::ControlBlock>()->container;
      if (pluginBlock == nullptr) {
         ::error("plugin export parameter has to be control block");
         return;
      }

      nlohmann::json pluginContainer;
      pluginContainer["name"] = plugin->toString();
      for (auto param : pluginBlock->getApplyParameters()->parameters) {
         if (param->toString() == "ext") {
            TypeTranslator type(param->type, typeMap_);
            pluginContainer["type"] = type.getName();
         }
      }

      ExporterFillVisitor insPlugin(refMap_, typeMap_, pluginContainer, insInit.getTemplateMapping(), insInit.getTemplateFields());
      pluginBlock->apply(insPlugin);
      extensions["plugins"] += pluginContainer;

      if (errorCount() > 0) {
         return;
      }
   }

   exporter_["exporter_init"] = templatesContainer;
   exporter_["exporter_fill"] = fillContainer;
   exporter_["exporter_plugins"] = extensions;

   // Compile template count.
   TemplateCountInspector templateCntIns(refMap_, typeMap_);
   templatesBlock->container->apply(templateCntIns);
   exporter_["template_cnt"] = templateCntIns.getCount();

   if (errorCount() > 0) {
      return;
   }

   if (!checkTemplateFile(options_.templatesDir_ + "/ipfix.c.tmplt") ||
       !checkTemplateFile(options_.templatesDir_ + "/ipfix.h.tmplt")) {
      return;
   }

   // Create files.
   inja::Environment env = inja::Environment(options_.templatesDir_ + "/", options_.genDir_ + "/");
   inja::Template tmpltSource = env.parse_template("ipfix.c.tmplt");
   env.write(tmpltSource, exporter_, "ipfix.c");

   inja::Template tmpltHeader = env.parse_template("ipfix.h.tmplt");
   env.write(tmpltHeader, exporter_, "ipfix.h");
}

} // namespace exporter
