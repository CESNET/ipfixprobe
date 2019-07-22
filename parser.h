/**
 * \file parser.h
 * \brief Contains parser code generation objects. Compiles parser P4 block.
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

#ifndef _BACKENDS_P4E_PARSER_H_
#define _BACKENDS_P4E_PARSER_H_

#include <nlohmann/json.hpp>

#include "ir/ir.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#include "options.h"
#include "utils.h"

namespace exporter
{

/**
 * Compiles expressions to parser specific code.
 */
class ParserExpressionHelper : public ConstructLogicalExpression
{
public:
   ParserExpressionHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, bool handleHeaders = true);
   bool preorder(const IR::Member *expr) override;
   bool preorder(const IR::PathExpression *expr) override;
   bool preorder(const IR::MethodCallExpression *expr) override;

private:
   bool headersFound_; /**< Used to determine string `headers` in path in tree. */
   bool handleHeaders_; /**< Handle `headers` expression in path. */

   /**
    * \brief Compiles lookahead extern function.
    *
    * \param [in] expr Node with function call.
    */
   void processLookahead(const IR::MethodCallExpression *expr);
};

/**
 * \brief Search and compile error codes used in P4 program.
 */
class ErrorCodesVisitor : public Inspector
{
public:
   ErrorCodesVisitor(nlohmann::json &returnCodes);
   bool preorder(const IR::Type_Error *e) override;

private:
   nlohmann::json &returnCodes_; /**< Container with available error codes. */
};

/**
 * \brief Compiles packet parser state.
 */
class ParserStateVisitor : public Inspector
{
public:
   ParserStateVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &parserState);
   bool preorder(const IR::ParserState *s) override;
   bool preorder(const IR::AssignmentStatement *s) override;
   bool preorder(const IR::Declaration *s) override;
   bool preorder(const IR::MethodCallExpression *expr) override;
   bool preorder(const IR::SelectExpression *s) override;
   bool preorder(const IR::SelectCase *s) override;
   bool preorder(const IR::PathExpression *p) override;

private:
   P4::ReferenceMap *refMap_;
   P4::TypeMap *typeMap_;

   nlohmann::json &parserState_; /**< Container for generated code. */
   nlohmann::json parserStateVars_; /**< Local variables defined in state. */

   std::string expression_;

   /**
    * \brief Compiles field extraction.
    *
    * \param [in] expr Node with extracted field.
    * \param [in] type Translated type of extracted field.
    * \param [in] fieldName Name of extracted field.
    * \param [in] alignment Alignment of extracted field.
    */
   void processExtractField(const IR::Expression *expr, TypeTranslator &type, std::string fieldName, unsigned alignment);
   /**
    * \brief Compiles extract extern function.
    *
    * \param [in] args Extract function call arguments.
    */
   void processExtract(const IR::Vector<IR::Argument> *args);
   /**
    * \brief Compiles advance extern function.
    *
    * \param [in] args Advance function call argument.
    */
   void processAdvance(const IR::MethodCallExpression *expr);
};

/**
 * \brief Compiles parser block and generates source code files.
 */
class ParserGenerator : public Generator
{
public:
   ParserGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   /**
    * \brief Compiles code and generates source code files.
    */
   void generate();

private:
   nlohmann::json parser_; /**< Container for generated C code. */

};

} // namespace exporter
#endif // _BACKENDS_P4E_PARSER_H_
