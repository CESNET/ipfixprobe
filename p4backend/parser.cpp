/**
 * \file parser.cpp
 * \brief Contains parser code generation objects. Compiles parser P4 block.
 *    Parser code generation is improved version of https://github.com/p4lang/p4c/tree/master/backends/ebpf
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

#include "parser.h"

namespace exporter
{


//
// ParserExpressionHelper
//


ParserExpressionHelper::ParserExpressionHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, bool handleHeaders)
   : ConstructLogicalExpression(refMap, typeMap), headersFound_(false), handleHeaders_(handleHeaders)
{
   setName("ParserExpressionHelper");
}

bool ParserExpressionHelper::preorder(const IR::Member *expr)
{
   visit(expr->expr);
   expression_ += ".";
   expression_ += expr->member.name.c_str();
   if (headersFound_ && handleHeaders_) {
      expression_ += "[0]";
      headersFound_ = false;
   }
   return false;
}

bool ParserExpressionHelper::preorder(const IR::PathExpression *expr)
{
   std::string path = expr->path->name.name.c_str();
   if (path == "headers" && handleHeaders_) {
      headersFound_ = true;
   }
   expression_ += path;
   return false;
}

bool ParserExpressionHelper::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();
   auto P4Lib = P4::P4CoreLibrary::instance;

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == P4Lib.packetIn.lookahead.name) {
         processLookahead(expr);
         return false;
      } else if (externMethod->method->name.name == P4Lib.packetIn.length.name) {
         expression_ += "packet_len";
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

void ParserExpressionHelper::processLookahead(const IR::MethodCallExpression *expr)
{
   if (expr->typeArguments->size() != 1) {
      ::error("Unable to compile lookahead %1%", expr);
   }

   TypeTranslator type((expr->typeArguments[0])[0], typeMap_);
   uint32_t width = type.getWidth();

   if (width <= 32) { // TODO: add 64 bit support
      std::string loaderFunc = "";
      std::string transformFunc = "";
      uint32_t toLoad;
      getLoadParameters(width, loaderFunc, transformFunc, toLoad);

      unsigned shiftBits = toLoad - width;
      if (shiftBits != 0) {
         expression_ += format("%1%(((%2%)(%3%(fpp_packet_start, BYTES(fpp_packet_offset_bits)) >> %4%) & FPP_MASK(%5%, %6%)));",
            transformFunc, type.getName(), loaderFunc, shiftBits, type.getName(), width);
      } else {
         expression_ += format("%1%((%2%)(%3%(fpp_packet_start, BYTES(fpp_packet_offset_bits))));",
            transformFunc, type.getName(), loaderFunc);
      }
   } else {
      ::error("Unable to compile lookahead with more than 32 bits");
   }
}


//
// ErrorCodesVisitor
//


ErrorCodesVisitor::ErrorCodesVisitor(nlohmann::json &returnCodes) : returnCodes_(returnCodes)
{
   setName("ErrorCodesVisitor");
   fillJsonTypeBasic(returnCodes_, "enum fpp_return_code", "fpp_return_code", typeEnum);
   returnCodes_["codes"] += "ParserDefaultReject";
   returnCodes_["codes"] += "OutOfMemory";
}

bool ErrorCodesVisitor::preorder(const IR::Type_Error *e)
{
   nlohmann::json codes;
   for (auto decl : *e->getDeclarations()) {
      returnCodes_["codes"] += decl->getName().name.c_str();
   }

   return true;
}


//
// ParserStateVisitor
//


ParserStateVisitor::ParserStateVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &parserState)
   : refMap_(refMap), typeMap_(typeMap), parserState_(parserState)
{
   setName("ParserStateVisitor");
   parserState_["direct_transition"] = false;
}

bool ParserStateVisitor::preorder(const IR::ParserState *s)
{
   parserStateVars_["name"] = s->name.name;
   for (auto tmp : s->components) {
      visit(tmp);
   }

   visit(s->selectExpression);
   return false;
}

bool ParserStateVisitor::preorder(const IR::AssignmentStatement *s)
{
   ParserExpressionHelper left(refMap_, typeMap_);
   ParserExpressionHelper right(refMap_, typeMap_);
   s->left->apply(left);
   s->right->apply(right);

   parserState_["statements"] += format("%1% = %2%;", left.getExpression(), right.getExpression());

   return false;
}

bool ParserStateVisitor::preorder(const IR::Declaration *s)
{
   nlohmann::json tmp;
   auto tmpDecl = dynamic_cast<const IR::Declaration_Variable *>(s);
   TypeTranslator type(tmpDecl->type, typeMap_);

   type.fillJson(tmp);
   tmp["name"] = s->name.name.c_str();
   parserState_["local_variables"] += tmp; // TODO
   return false;
}

bool ParserStateVisitor::preorder(const IR::MethodCallExpression *expr)
{
   auto methodInst = P4::MethodInstance::resolve(expr, refMap_, typeMap_);
   auto externMethod = methodInst->to<P4::ExternMethod>();
   auto P4Lib = P4::P4CoreLibrary::instance;

   if (externMethod != nullptr) {
      if (externMethod->method->name.name == P4Lib.packetIn.extract.name) {
         processExtract(expr->arguments);
         return false;
      } else if (externMethod->method->name.name == P4Lib.packetIn.advance.name) {
         processAdvance(expr);
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

bool ParserStateVisitor::preorder(const IR::SelectExpression *s)
{
   ParserExpressionHelper ins(refMap_, typeMap_);
   if (s->select->components.size() != 1) {
      ::error("ListExpression with more than 1 expression not supported yet %1%", s);
   }
   s->select->components.at(0)->apply(ins);

   parserState_["select_cond"] = ins.getExpression();
   for (auto c : s->selectCases) {
      visit(c);
   }
   return false;
}

bool ParserStateVisitor::preorder(const IR::SelectCase *s)
{
   nlohmann::json tmp;
   ParserExpressionHelper ins(refMap_, typeMap_);

   if (s->keyset->is<IR::DefaultExpression>()) {
      tmp["default"] = true;
      tmp["cond"] = "";
   } else {
      tmp["default"] = false;
      s->keyset->apply(ins);
      tmp["cond"] = ins.getExpression();
   }
   tmp["destination"] = s->state->path->name.name.c_str();

   parserState_["select_cases"] += tmp;
   return false;
}

bool ParserStateVisitor::preorder(const IR::PathExpression *p)
{
   auto parent = getContext();
   if (parent != nullptr) {
      if (parent->node->is<IR::ParserState>()) {
         parserState_["direct_transition"] = true;
         parserState_["next_state"] = p->path->name.name.c_str();
      }
   }
   return false;
}

void ParserStateVisitor::processExtractField(const IR::Expression *expr, TypeTranslator &type, std::string fieldName, unsigned alignment)
{
   uint32_t toLoad;
   uint32_t width = type.getWidth();
   uint32_t shiftBits;

   ParserExpressionHelper ins(refMap_, typeMap_);
   expr->apply(ins);

   std::string path = format("%1%.%2%", ins.getExpression(), fieldName);
   std::string loaderFunc = "";
   std::string transformFunc = "";
   std::string code = "";
   std::string mask = "";

   if (width <= 64) {
      getLoadParameters(width + alignment, loaderFunc, transformFunc, toLoad);
      shiftBits = toLoad - (width + alignment);

      if (width != toLoad) {
         mask = format(" & FPP_MASK(%1%, %2%)", type.getName(), width);
      }
      if (shiftBits != 0) {
         if (toLoad <= 64) {
            code = format("%1% = (%3%)(%2%(%4%(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> %5%)%6%;",
               path, transformFunc, type.getName(), loaderFunc, shiftBits, mask); // TODO: test
            //code = format("%1% = %2%((%3%)(%4%(fpp_packet_start, BYTES(fpp_packet_offset_bits)) >> %5%)%6%);",
            //   path, transformFunc, type.getName(), loaderFunc, shiftBits, mask);
         } else {
            // This code is used when bits to load are > 64 (width + alignment > 64).
            // This means we have to load 64 bits and 8 additional bits and put it together.

            // Load 64 bits
            std::string part1 = format("%1%((%2%)(%3%(fpp_packet_start, BYTES(fpp_packet_offset_bits)) << %4%)%5%)",
               transformFunc, type.getName(), loaderFunc, 8 - shiftBits, mask);

            // Load 8 bits
            std::string part2 = format("((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + %1%)) >> %2%) & FPP_MASK(uint8_t, %3%))",
               width, shiftBits, 8 - shiftBits);

            code = format("%1% = (%2%)(%3%) | (%2%)(%4%);", path, type.getName(), part1, part2);
         }
      } else {
         code = format("%1% = %2%((%3%)(%4%(fpp_packet_start, BYTES(fpp_packet_offset_bits)))%5%);",
         path, transformFunc, type.getName(), loaderFunc, mask);
      }

      parserState_["statements"] += code;
      parserState_["statements"] += format("fpp_packet_offset_bits += %1%;", width);
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
            code = format("%1%[%2%] = (uint8_t)((%3%(fpp_packet_start, BYTES(fpp_packet_offset_bits + %4%)) >> %5%) & FPP_MASK(uint8_t, %7%));",
               path, i, loaderFunc, i * loadWidth, shiftBits, width % 8);
         } else {
            code = format("%1%[%2%] = (uint8_t)(%3%(fpp_packet_start, BYTES(fpp_packet_offset_bits + %4%)) >> %5%);",
               path, i, loaderFunc, i * loadWidth, shiftBits);
         }
         parserState_["statements"] += code;
      }
      parserState_["statements"] += format("fpp_packet_offset_bits += %1%;", width);
   }
}

void ParserStateVisitor::processExtract(const IR::Vector<IR::Argument> *args)
{
   if (args->size() != 1) {
      ::error("Variable length header fields not supported");
      return;
   }

   auto expr = args->at(0)->expression;
   auto type = typeMap_->getType(expr);

   auto headerType = type->to<IR::Type_Header>();
   if (headerType == nullptr) {
      ::error("Extraction to non header type not supported");
      return;
   }

   auto member = expr->to<IR::Member>();
   if (member != nullptr) {
      auto pathExpr = member->expr->to<IR::PathExpression>();
      if (pathExpr != nullptr) {
         if (pathExpr->path->name.name == "headers") {
            ParserExpressionHelper ins(refMap_, typeMap_, false);
            expr->apply(ins);
            TypeTranslator tmp(headerType, typeMap_);

            parserState_["statements"] += format("if (fpp_packet_start + BYTES(fpp_packet_offset_bits + %1%) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }", tmp.getWidth());
            parserState_["statements"] += format("if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[%1%] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }", tmp.getNameShort());
            parserState_["statements"] += format("%1% = &parser->%2%[parser->hdr_counts[%3%]++];", ins.getExpression(), member->member.name.c_str(), tmp.getNameShort());
            parserState_["statements"] += format("hdr = &parser->links[parser->link_count++];");
            parserState_["statements"] += format("hdr->type = %1%;", tmp.getNameShort());
            parserState_["statements"] += format("hdr->data = %1%;", ins.getExpression());
            parserState_["statements"] += format("hdr->header_offset = fpp_packet_offset_bits / 8;");
            parserState_["statements"] += format("hdr->next = NULL;");
            parserState_["statements"] += format("if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }");
         }
      }
   }

   unsigned alignment = 0;
   for (auto field : headerType->fields) {
      auto fieldType = typeMap_->getType(field);
      TypeTranslator tmp(fieldType, typeMap_);

      processExtractField(expr, tmp, field->name.name.c_str(), alignment);
      alignment += tmp.getWidth();
      alignment %= 8;

      ParserExpressionHelper ins(refMap_, typeMap_);
      expr->apply(ins);
      std::string path = format("%1%.%2%", ins.getExpression(), field->name.name.c_str());

      addDebugParserField(parserState_, tmp, path);
   }
   if (alignment != 0) {
      std::cerr << "warning: extracted header " << type->to<IR::Type_StructLike>()->name.name << " is not aligned to 8 bits" << std::endl;
   }
}

void ParserStateVisitor::processAdvance(const IR::MethodCallExpression *expr)
{
   auto arg = expr->arguments->at(0);
   ParserExpressionHelper ins(refMap_, typeMap_);
   arg->apply(ins);

   parserState_["statements"] += "fpp_packet_offset_bits += " + ins.getExpression() + ";";
}


//
// ParserGenerator
//


ParserGenerator::ParserGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap)
   : Generator(options, topLevel, refMap, typeMap)
{
}

void ParserGenerator::generate()
{
   auto main = topLevel_->getMain();
   if (main == nullptr) {
      ::error("Package main not found");
      return;
   }
   auto pb = main->getParameterValue("prs")->to<IR::ParserBlock>();
   if (pb == nullptr) {
      ::error("No parser block found");
      return;
   }

   auto params = pb->container->getApplyParameters();
   for (auto p : *params) {
      if (p->name.name == "headers") {
         nlohmann::json tmp;
         auto type = typeMap_->getType(p->type)->to<IR::Type_Type>()->type;
         TypeTranslator t(type, typeMap_);

         t.fillJson(tmp);
         tmp["name"] = p->name.name.c_str();
         parser_["parsed_headers"] = tmp;
      }
   }

   // Process error codes.
   nlohmann::json returnCodes;
   ErrorCodesVisitor errorIns(returnCodes);
   topLevel_->getProgram()->apply(errorIns);
   parser_["return_codes"] = returnCodes;

   nlohmann::json errorCode;
   nlohmann::json packetStart;
   nlohmann::json packetEnd;
   nlohmann::json packetOffsetBits;
   nlohmann::json packetPtr;
   nlohmann::json packetLen;
   nlohmann::json outHeaders;
   nlohmann::json currentHeader;
   nlohmann::json lastHeader;

   fillJsonTypeBasic(errorCode, "enum fpp_return_code", "fpp_return_code", typeEnum);
   errorCode["name"] = "fpp_error_code";
   errorCode["initializer"] = "ParserDefaultReject";
   fillJsonTypeBasic(packetStart, "const uint8_t *", "uint8_t", typeIntU);
   packetStart["name"] = "fpp_packet_start";
   packetStart["initializer"] = "packet_ptr";
   fillJsonTypeBasic(packetEnd, "const uint8_t *", "uint8_t", typeIntU);
   packetEnd["name"] = "fpp_packet_end";
   packetEnd["initializer"] = "packet_ptr + packet_len";
   fillJsonTypeBasic(packetOffsetBits, "uint32_t", "uint32_t", typeIntU);
   packetOffsetBits["name"] = "fpp_packet_offset_bits";
   packetOffsetBits["initializer"] = "0";

   fillJsonTypeBasic(packetPtr, "const uint8_t *", "uint8_t", typeIntU);
   packetPtr["name"] = "packet_ptr";
   fillJsonTypeBasic(packetLen, "uint32_t", "uint32_t", typeIntU);
   packetLen["name"] = "packet_len";
   fillJsonTypeBasic(outHeaders, "struct packet_hdr_s **", "packet_hdr_s", typeStruct);
   outHeaders["name"] = "out";

   fillJsonTypeBasic(currentHeader, "struct packet_hdr_s *", "packet_hdr_s", typeStruct);
   currentHeader["name"] = "hdr";
   currentHeader["initializer"] = "NULL";
   fillJsonTypeBasic(lastHeader, "struct packet_hdr_s *", "packet_hdr_s", typeStruct);
   lastHeader["name"] = "last_hdr";
   lastHeader["initializer"] = "NULL";

   parser_["packet_var"] = packetPtr;
   parser_["packet_len_var"] = packetLen;
   parser_["out_headers"] = outHeaders;
   parser_["headers_enum"] = "enum fpp_header";

   parser_["local_variables"] += errorCode;
   parser_["local_variables"] += packetStart;
   parser_["local_variables"] += packetEnd;
   parser_["local_variables"] += packetOffsetBits;
   parser_["local_variables"] += currentHeader;
   parser_["local_variables"] += lastHeader;

   // Process parser local variables.
   for (auto decl : pb->container->parserLocals) {
      nlohmann::json tmp;
      auto tmpDecl = dynamic_cast<const IR::Declaration_Variable *>(decl);
      TypeTranslator type(tmpDecl->type, typeMap_);

      type.fillJson(tmp);
      tmp["name"] = decl->name.name.c_str();
      parser_["local_variables"] += tmp;
   }

   // Process parser states.
   for (auto state : pb->container->states) {
      nlohmann::json tmp;
      auto stateName = state->name.name;
      if (stateName == IR::ParserState::reject ||
         stateName == IR::ParserState::accept ||
         stateName == "noMatch") {
         continue;
      }
      ParserStateVisitor ins(refMap_, typeMap_, tmp);
      state->apply(ins);

      tmp["name"] = stateName;
      parser_["states"] += tmp;
   }

   // Process global headers.
   for (auto obj : topLevel_->getProgram()->objects) {
      if (obj->is<IR::Type_Header>()) {
         TypeTranslator type(obj->to<IR::Type>(), typeMap_);
         nlohmann::json tmp;
         type.fillJson(tmp);

         parser_["headers"] += tmp;
      }
   }

   nlohmann::json linkedList;
   nlohmann::json outType;
   nlohmann::json outData;
   nlohmann::json outOffset;
   nlohmann::json outNext;

   fillJsonTypeBasic(outType, "enum fpp_header", "fpp_header", typeEnum);
   outType["name"] = "type";
   fillJsonTypeBasic(outData, "void *", "void *", typeVoid);
   outData["name"] = "data";
   fillJsonTypeBasic(outOffset, "uint32_t", "uint32_t", typeIntU);
   outOffset["name"] = "header_offset";
   fillJsonTypeBasic(outNext, "struct packet_hdr_s *", "packet_hdr_s *", typeStruct);
   outNext["name"] = "next";

   fillJsonTypeBasic(linkedList, "struct packet_hdr_s", "packet_hdr_s", typeStruct);
   linkedList["fields"] += outType;
   linkedList["fields"] += outData;
   linkedList["fields"] += outOffset;
   linkedList["fields"] += outNext;

   parser_["linked_list"] = linkedList;

   if (errorCount() > 0) {
      return;
   }

   if (!checkTemplateFile(options_.templatesDir_ + "/parser.c.tmplt") ||
       !checkTemplateFile(options_.templatesDir_ + "/parser.h.tmplt")) {
      return;
   }

   inja::Environment env = inja::Environment(options_.templatesDir_ + "/", options_.genDir_ + "/");
   inja::Template tmpltSource = env.parse_template("parser.c.tmplt");
   env.write(tmpltSource, parser_, "parser.c");

   inja::Template tmpltHeader = env.parse_template("parser.h.tmplt");
   env.write(tmpltHeader, parser_, "parser.h");
}

} // namespace exporter
