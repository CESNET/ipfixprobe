/**
 * \file plugin.h
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

#ifndef _BACKENDS_P4E_PLUGIN_H_
#define _BACKENDS_P4E_PLUGIN_H_

#include <vector>
#include <nlohmann/json.hpp>

#include "ir/ir.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#include "options.h"
#include "utils.h"

namespace exporter {

/**
 * Compiles expressions to plugin specific code.
 */
class PluginExpressionHelper : public ConstructLogicalExpression
{
public:
   PluginExpressionHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   bool preorder(const IR::Member *expr) override;
   bool preorder(const IR::PathExpression *expr) override;
   bool preorder(const IR::MethodCallExpression *expr) override;

private:
   /**
    * \brief Compile extract_re extern function.
    *
    * \param [in] expr Node wih call expression and arguments.
    */
   void compileExtractRe(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile lookahead_re extern function.
    *
    * \param [in] expr Node wih call expression and arguments.
    */
   void compileLookaheadRe(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile match extern function.
    *
    * \param [in] expr Node wih call expression and arguments.
    */
   void compileMatch(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile lookahead extern function.
    *
    * \param [in] expr Node wih call expression and arguments.
    */
   void compileLookahead(const IR::MethodCallExpression *expr);
};

/**
 * \breif Generates code of lexer.
 */
class LexerBuilder : public CodeBuilder
{
public:
   LexerBuilder(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container);
   std::string compileDefinition(const IR::Expression *arg1, const IR::Expression *arg2, bool extractInput, bool consumeInput, bool matchArguments = false);
   std::string getRegex(const IR::Expression *arg1);
   std::string compileFuncName(const IR::Expression *arg1);
   std::string compileCall(const IR::Expression *arg1, const IR::Expression *arg2, bool matchArguments = false);

private:
   /**
    * \brief Check regular expression string.
    *
    * \brief [in] regex Pointer to regular expression string.
    * \brief [inout] marker Used to save position of end of group (')').
    * \return Number of POSIX groups found.
    */
   int checkRegex(const char *regex, const char **marker);
   /**
    * \brief Check number of arguments in extract_re call.
    *
    * \param [in] arg1 Specified regex argument.
    * \param [in] arg2 List of output variables
    * \return True when regex groups and number of variables match.
    */
   bool checkNumArgs(const IR::Expression *arg1, const IR::Expression *arg2);
   /**
    * \brief Get number of parameters in output variables list.
    *
    * \param [in] arg2 List of output variables
    * \return Number of variables.
    */
   int getParamCnt(const IR::Expression *arg2);
   /**
    * \brief Compile prototype of regex function.
    *
    * \param [in] arg1 Specified regex argument.
    * \param [in] arg2 List of output variables
    * \param [in] matchArguments True means that checking regex string groups and available arguments will be performed.
    */
   void compilePrototype(const IR::Expression *arg1, const IR::Expression *arg2, bool matchArguments);
   /**
    * \brief Compiler regex function body.
    *
    * \param [in] regex String with regular expression.
    * \param [in] paramCnt Number of output parameters.
    * \param [in] extractInput Extract input to output parameters.
    * \param [in] consumeInput Update payload pointer on success match.
    */
   void compileCode(const std::string &regex, int paramCnt, bool extractInput, bool consumeInput);
};

/**
 * \brief Helper that finds all function calls and compiles C code for them.
 */
class LexerHelper : public CodeBuilder, public Inspector
{
public:
   LexerHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container);
   bool preorder(const IR::MethodCallExpression *expr) override;

private:
   static std::vector<std::string> compiledFunctions; /**< Identifiers of already compiled functions. */

   /**
    * \brief Check if function is already compiled.
    *
    * \param [in] funcName Name of the function.
    * \return True when function exists.
    */
   static bool functionAlreadyCompiled(const std::string &funcName);
   /**
    * \brief Compile extract_re function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileParse(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile lookahead function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileLookahead(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile match function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileMatch(const IR::MethodCallExpression *expr);
};

/**
 * \brief Compiles plugin parser block.
 */
class PluginVisitor : public CodeBuilder, public UnsupportedStatementInspector
{
public:
   PluginVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container);
   bool preorder(const IR::P4Parser *p) override;
   bool preorder(const IR::ParserState *s) override;
   bool preorder(const IR::AssignmentStatement *s) override;
   bool preorder(const IR::Declaration *s) override;
   bool preorder(const IR::MethodCallStatement *stat) override;
   bool preorder(const IR::MethodCallExpression *expr) override;
   bool preorder(const IR::SelectExpression *s) override;
   bool preorder(const IR::SelectCase *s) override;
   bool preorder(const IR::PathExpression *p) override;

private:
   /**
    * \brief Compile extract_re exrtern function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileExtractRe(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile match extern function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileMatch(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile strcpy extern function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileStrcpy(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile to_number extern function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileToNumber(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile extract extern function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileExtract(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile advance  extern function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileAdvance(const IR::MethodCallExpression *expr);
   /**
    * \brief Compile extract_string extern function call.
    *
    * \param [in] expr Node with function call expression.
    */
   void compileExtractString(const IR::MethodCallExpression *expr);
   /**
    * \brief Compiles extraction of field from packet.
    *
    * \param [in] expr Node with extracted field.
    * \param [in] type Translated type of extracted field.
    * \param [in] fieldName Name of extracted field.
    * \param [in] alignment Alignment of extracted field.
    * \param [in] offset_bits Offset bits in byte.
    */
   void compileExtractField(const IR::Expression *expr, TypeTranslator &type, std::string fieldName, unsigned alignment, unsigned offset_bits);
   /**
    * \brief Check if variable is string.
    *
    * \param [in] expr Node with function call argument.
    */
   bool checkVarIsString(const IR::Expression *expr);
};

/**
 * \brief Compiles plugin post create, pre update parser blocks and export control blocks and generates source code files.
 */
class PluginGenerator : public Generator
{
public:
   PluginGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   /**
    * \brief Compiles code and generates source code files.
    */
   void generate();

private:
   nlohmann::json plugin_; /**< Container for generated C code. */

   /**
    * \brief Compiles plugin code.
    *
    * \param [in] plugin Node with plugin package.
    */
   void compilePlugin(const IR::PackageBlock *plugin);
};

} // namespace exporter
#endif // _BACKENDS_P4E_PLUGIN_H_
