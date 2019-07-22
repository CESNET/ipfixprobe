/**
 * \file utils.cpp
 * \brief Contains useful objects for code generation, node inspection and logging.
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

#include <fstream>
#include <experimental/filesystem>
#include <nlohmann/json.hpp>

#include "ir/ir.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#include "utils.h"

namespace fs = std::experimental::filesystem;

namespace exporter {

void getLoadParameters(uint32_t width, std::string &loaderFunc, std::string &transformFunc, uint32_t &toLoad)
{
   if (width <= 8) {
      loaderFunc = "load_byte";
      toLoad = 8;
   } else if (width <= 16) {
      loaderFunc = "load_half";
      transformFunc = "ntohs";
      toLoad = 16;
   } else if (width <= 32) {
      loaderFunc = "load_word";
      transformFunc = "ntohl";
      toLoad = 32;
   } else if (width <= 64) {
      loaderFunc = "load_dword";
      transformFunc = "ntohll";
      toLoad = 64;
   } else if (width <= 72) {
      loaderFunc = "load_dword";
      transformFunc = "ntohll";
      toLoad = 72;
   } else {
      BUG("unexpected load width %1%", width);
   }
}

void fillJsonTypeBasic(nlohmann::json &container, std::string typeName, std::string typeNameShort, variableType type)
{
   container["type_name"] = typeName;
   container["type_name_short"] = typeNameShort;
   container["type"] = type;
}

void fillJsonTypeWidth(nlohmann::json &container, uint32_t width, uint32_t implementationWidth)
{
   container["width"] = width;
   container["width_implementation"] = implementationWidth;
}

void fillJsonTypeArray(nlohmann::json &container, bool array, unsigned arraySize)
{
    container["array"] = array;
    container["array_size"] = arraySize;
}

void fillJsonVar(nlohmann::json &container, std::string typeName, std::string typeNameShort, variableType type, std::string name)
{
    container["name"] = name;
    fillJsonTypeBasic(container, typeName, typeNameShort, type);
}

bool fileExists(const std::string &file)
{
   std::error_code errorCode;
   fs::file_status fileStat = fs::status(file, errorCode);

   if (errorCode.value() ||
      !is_regular_file(fileStat)) {
      return false;
   }

   std::ifstream ifs(file.c_str(), std::ifstream::in);
   bool ok = ifs.good();

   ifs.close();
   return ok;
}

bool generateOutputFolder(const std::string &dir)
{
   std::error_code errorCode;
   // Check if the path exits, if yes, remove everything
   if (fs::exists(dir)) {
      fs::remove_all(dir);
   }

   fs::create_directories(dir, errorCode);

   if (errorCode.value()) {
      ::error("Could not create directory '%1%': %2%", dir, errorCode.message());
      return false;
   }
   return true;
}

bool copy(const std::string &src, const std::string &dst)
{
   std::error_code errorCode;
   fs::copy(src, dst, fs::copy_options::recursive, errorCode);

   if (errorCode.value()) {
      ::error("Could not copy '%1%' to '%2%': %3%", src, dst, errorCode.message());
      return false;
   }

   return true;
}

//
// TypeTranslator
//

TypeTranslator::TypeTranslator(const IR::Type *type, P4::TypeMap *typeMap)
   : type_(type), typeMap_(typeMap)
{
   initialize();
   compileType(type);
}
TypeTranslator::TypeTranslator(const IR::StructField *decl, P4::TypeMap *typeMap)
   : type_(decl->type), typeMap_(typeMap)
{
   initialize();
   compileTypeWithAnnotations(decl);
}
TypeTranslator::TypeTranslator(const IR::Declaration_Variable *decl, P4::TypeMap *typeMap)
   : type_(decl->type), typeMap_(typeMap)
{
   initialize();
   compileTypeWithAnnotations(decl);
}

void TypeTranslator::initialize()
{
   decl_ = false;
   width_ = 0;
   implementationWidth_ = 0;
   array_ = false;
   string_ = false;
   arraySize_ = 0;
   typeCode_ = typeUnknown;
   typeName_ = "";
   typeNameShort_ = "";
}

void TypeTranslator::compileTypeWithAnnotations(const IR::Declaration *decl)
{
   auto stringAnnotation = decl->getAnnotation("string");
   if (stringAnnotation != nullptr) {
      long len = std::stol(stringAnnotation->body.at(0)->text.c_str());
      if (len <= 0) {
         ::error("string %1% cannot have negative or zero length", stringAnnotation);
         return;
      }

      typeCode_ = typeString;
      width_ = len * 8;
      implementationWidth_ = (width_ / 8) * 8 + (width_ % 8 ? 8 : 0);
      array_ = true;
      string_ = true;
      arraySize_ = width_ / 8 + (width_ % 8 ? 1 : 0);

      typeName_ = "uint8_t";
      typeNameShort_ = typeName_;

      return;
   }

   compileType(type_);
}

void TypeTranslator::compileType(const IR::Type *type)
{
   if (type->is<IR::Type_Boolean>()) {
      width_ = 8;
      implementationWidth_ = 8;
      typeName_ = "uint8_t";
      typeNameShort_ = typeName_;
      typeCode_ = typeBool;
   } else if (type->is<IR::Type_Bits>()) {
      auto tmp = type->to<IR::Type_Bits>();
      width_ = tmp->width_bits();
      typeCode_ = typeIntU;

      if (width_ <= 8) {
         implementationWidth_ = 8;
      } else if (width_ <= 16) {
         implementationWidth_ = 16;
      } else if (width_ <= 32) {
         implementationWidth_ = 32;
      } else if (width_ <= 64) {
         implementationWidth_ = 64;
      } else {
         implementationWidth_ = (width_ / 8) * 8 + (width_ % 8 ? 8 : 0);
         array_ = true;
         arraySize_ = width_ / 8 + (width_ % 8 ? 1 : 0);
      }

      std::string preffix = "u";
      if (tmp->isSigned) {
         preffix = "";
         typeCode_ = typeInt;
      }
      if (array_) {
         typeName_ = format("%1%int8_t", preffix);
      } else {
         typeName_ = format("%1%int%2%_t", preffix, implementationWidth_);
      }
      typeNameShort_ = typeName_;
   } else if (type->is<IR::Type_StructLike>()) {
      auto tmp = type->to<IR::Type_StructLike>();
      std::string preffix = "";
      decl_ = true;

      if (type->is<IR::Type_Header>()) {
         preffix = "struct ";
         typeCode_ = typeHeader;
      } else if (type->is<IR::Type_Struct>()) {
         preffix = "struct ";
         typeCode_ = typeStruct;
      } else if (type->is<IR::Type_HeaderUnion>()) {
         preffix = "union ";
         typeCode_ = typeUnion;
      }
      typeNameShort_ = tmp->name.name;
      typeName_ = format("%1%%2%", preffix, typeNameShort_);

      for (auto f : tmp->fields) {
         TypeTranslator tmpType(f, typeMap_);
         fields_.push_back(tmpType);
         fieldNames_.push_back(f->name.name.c_str());
         width_ += tmpType.getWidth();
         implementationWidth_ += tmpType.getImplementationWidth();
      }
   } else if (type->is<IR::Type_Name>()) {
      auto tmp = type->to<IR::Type_Name>();
      auto tmpType = typeMap_->getType(tmp->path);

      std::string preffix = "";
      if (tmpType->is<IR::Type_Header>()) {
         preffix = "struct ";
         typeCode_ = typeHeader;
      } else if (tmpType->is<IR::Type_Struct>()) {
         preffix = "struct ";
         typeCode_ = typeStruct;
      } else if (tmpType->is<IR::Type_HeaderUnion>()) {
         preffix = "union ";
         typeCode_ = typeUnion;
      }
      typeNameShort_ = tmp->path->name.name;
      typeName_ = format("%1%%2%", preffix, typeNameShort_);
   } else {
      ::error("Type not supported: %1%", type);
   }
}

void TypeTranslator::fillJson(nlohmann::json &container) const
{
   fillJsonTypeBasic(container, typeName_, typeNameShort_, typeCode_);
   fillJsonTypeWidth(container, width_, implementationWidth_);
   if (array_) {
      fillJsonTypeArray(container, array_, arraySize_);
   }

   if (decl_) {
      for (unsigned i = 0; i < fields_.size(); i++) {
         nlohmann::json tmp;

         fields_[i].fillJson(tmp);
         tmp["name"] = fieldNames_[i];
         container["fields"] += tmp;
      }
   }
}

uint32_t TypeTranslator::getWidth() const
{
   return width_;
}

uint32_t TypeTranslator::getImplementationWidth() const
{
   return implementationWidth_;
}

int TypeTranslator::getArrayLength() const
{
   return (array_ ? arraySize_ : -1);
}

int TypeTranslator::isString() const
{
   return string_;
}

std::string TypeTranslator::getName() const
{
   return typeName_;
}

std::string TypeTranslator::getNameShort() const
{
   return typeNameShort_;
}


//
// CodeBuilder
//


CodeBuilder::CodeBuilder(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container, int spacesPerIndent)
   : refMap_(refMap), typeMap_(typeMap), container_(container), indentLevel_(0), spacesPerIndent_(spacesPerIndent)
{
}

void CodeBuilder::addCode(nlohmann::json &container, const std::string &name, const std::string &code)
{
   container[name] += code;
}

void CodeBuilder::addStatement(const std::string &stat)
{
   addCode(container_, "statements", std::string(indentLevel_ * spacesPerIndent_, ' ') + stat);
}

void CodeBuilder::increaseIndent()
{
   indentLevel_++;
}

void CodeBuilder::decreaseIndent()
{
   indentLevel_--;
   if (indentLevel_ < 0) {
      indentLevel_ = 0;
   }
}


//
// Generator
//


Generator::Generator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : options_(options), topLevel_(topLevel), refMap_(refMap), typeMap_(typeMap)
{
}

bool Generator::checkTemplateFile(const std::string &file)
{
   if (!fileExists(file)) {
      ::error("template file %1% does not exists", file);
      return false;
   }

   return true;
}


//
// ConstructArithmeticExpression
//


ConstructArithmeticExpression::ConstructArithmeticExpression(P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : refMap_(refMap), typeMap_(typeMap), expression_("")
{
   setName("ConstructArithmeticExpression");
}

bool ConstructArithmeticExpression::preorder(const IR::BoolLiteral *lit)
{
   expression_ += (lit->value ? "1" : "0");
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Add *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") + (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Sub *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") - (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Mul *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") * (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Div *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") / (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Mod *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") % (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Shl *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") << (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Shr *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") >> (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::BXor *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") ^ (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::BAnd *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") & (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::BOr *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") | (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Constant *expr)
{
   if (!expr->fitsLong()) {
      BUG("%1% does not fit to long", expr);
   }
   expression_ += std::to_string(expr->asLong());
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Member *expr)
{
   visit(expr->expr);
   expression_ += format(".%1%", expr->member.name.c_str());
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::PathExpression *expr)
{
   expression_ += expr->path->name.name.c_str();
   return false;
}

bool ConstructArithmeticExpression::preorder(const IR::Cast *expr)
{
   TypeTranslator destType(expr->destType, typeMap_);
   expression_ += "(" + destType.getName() + ")";
   expression_ += "(";
   visit(expr->expr);
   expression_ += ")";

   TypeTranslator typeExpr(typeMap_->getType(expr->expr), typeMap_);
   if ((destType.getWidth() <= 64 && typeExpr.getWidth() > 64) ||
       (destType.getWidth() > 64 && typeExpr.getWidth() <= 64)) {
      ::error("cast between integer <= 64 bits and integer > 64 not supported: %1%", expr);
   }
   return false;
}

std::string ConstructArithmeticExpression::getExpression() const
{
   return expression_;
}


//
// ConstructLogicalExpression
//


ConstructLogicalExpression::ConstructLogicalExpression(P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : ConstructArithmeticExpression(refMap, typeMap)
{
   setName("ConstructLogicalExpression");
}

bool ConstructLogicalExpression::preorder(const IR::LOr *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") || (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructLogicalExpression::preorder(const IR::LAnd *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") && (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructLogicalExpression::preorder(const IR::LNot *expr)
{
   expression_ += "!";
   visit(expr->expr);
   return false;
}

bool ConstructLogicalExpression::preorder(const IR::Equ *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") == (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructLogicalExpression::preorder(const IR::Neq *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") != (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructLogicalExpression::preorder(const IR::Geq *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") >= (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructLogicalExpression::preorder(const IR::Grt *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") > (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructLogicalExpression::preorder(const IR::Leq *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") <= (";
   visit(expr->right);
   expression_ += ")";
   return false;
}

bool ConstructLogicalExpression::preorder(const IR::Lss *expr)
{
   expression_ += "(";
   visit(expr->left);
   expression_ += ") < (";
   visit(expr->right);
   expression_ += ")";
   return false;
}


//
// ConstructExpression
//


ConstructExpression::ConstructExpression(P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : ConstructLogicalExpression(refMap, typeMap)
{
   setName("ConstructExpression");
}

} // namespace exporter
