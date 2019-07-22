/**
 * \file cache.h
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

#ifndef _BACKENDS_P4E_CACHE_H_
#define _BACKENDS_P4E_CACHE_H_

#include <vector>
#include <nlohmann/json.hpp>

#include "ir/ir.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#include "options.h"
#include "utils.h"

namespace exporter {

/**
 * Compiles expressions to cache specific code.
 */
class CacheExpressionHelper : public ConstructExpression
{
public:
   CacheExpressionHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   bool preorder(const IR::Member *expr) override;
   bool preorder(const IR::PathExpression *expr) override;
   bool preorder(const IR::MethodCallExpression *expr) override;

private:
   /**
    * \brief True when `headers` are found in expression (for example in path `headers.ipv4.src_addr`).
    */
   bool headersFound_;
   /**
    * \brief True when `flow` are found in expression (for example `flow.src_addr`).
    */
   bool flowFound_;

   /**
    * \brief Compiles is_present extern function.
    */
   void processPresent(const IR::Vector<IR::Argument> *args);
   /**
    * \brief Compiles is_next extern function.
    */
   void processNext(const IR::Vector<IR::Argument> *args);
   /**
    * \brief Check if cache extern method parameters are OK.
    *
    * \param [in] args Node with function arguments.
    * \return True if parameters are OK, false otherwise.
    */
   bool checkCacheMethods(const IR::Vector<IR::Argument> *args);
};

/**
 * \brief Base class for compilation of control blocks.
 */
class CacheVisitor : public CodeBuilder, public UnsupportedStatementInspector
{
public:
   CacheVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container);
   bool preorder(const IR::Declaration *s) override;
   bool preorder(const IR::BlockStatement *s) override;
   bool preorder(const IR::AssignmentStatement *s) override;
   bool preorder(const IR::IfStatement *s) override;
};

/**
 * \brief Used for compilation of flow cache create function.
 */
class CacheCreateVisitor : public CacheVisitor
{
public:
   CacheCreateVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container);
   bool preorder(const IR::MethodCallStatement *s) override;
   bool preorder(const IR::MethodCallExpression *expr) override;

   /**
    * \brief Generates code for case when there are two headers of same type in linked list or there are conflicting headers.
    *
    * \param [out] cond Variable to store generated condition at.
    */
   void setSplitStatement(const std::string &cond);

private:
   /**
    * \brief Process add_to_key extern function.
    *
    * \param [in] args Extern function arguments.
    */
   void processAddToKey(const IR::Vector<IR::Argument> *args);
};

/**
 * \brief Used for compilation of flow cache update function.
 */
class CacheUpdateVisitor : public CacheVisitor
{
public:
   CacheUpdateVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container);

   bool preorder(const IR::MethodCallStatement *s) override;
   bool preorder(const IR::MethodCallExpression *expr) override;

   /**
    * \brief Generates code for case when there are two headers of same type in linked list or there are conflicting headers.
    *
    * \param [out] cond Variable with condition that will be used in if statement.
    */
   void setSplitStatement(const std::string &cond);
};

/**
 * \brief Used to search calls of set_conflicting_headers extern function in control block
 *    and compilation of condition that will be later used to cancel processing of linked list.
 */
class ConflictingTypesHelper : public Inspector
{
public:
   ConflictingTypesHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   bool preorder(const IR::MethodCallExpression *expr) override;

   /**
    * \brief Gets generated condition.
    *
    * \return String with generated condition.
    */
   std::string getCond() const;

private:
   P4::ReferenceMap *refMap_;
   P4::TypeMap *typeMap_;
   std::string cond_; /**< String with generated condition. */
};

/**
 * \brief Used to get total number of added bytes to key. Search all calls of add_to_key function.
 */
class ComputeKeyWidthHelper : public Inspector
{
public:
   ComputeKeyWidthHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   bool preorder(const IR::MethodCallExpression *expr) override;

   /**
    * \brief Gets computed with.
    *
    * \return Number of bits.
    */
   uint32_t getWidth() const;

private:
   P4::ReferenceMap *refMap_;
   P4::TypeMap *typeMap_;
   uint32_t width_; /**< Width in number of bits. */
};

/**
 * \brief Compiles cache create and update control blocks and generates source code files.
 */
class CacheGenerator : public Generator
{
public:
   CacheGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   /**
    * \brief Compiles code and generates source code files.
    */
   void generate();

private:
   nlohmann::json cache_; /**< Container for generated C code. */

   /**
    * \brief Compiles create control block.
    *
    * \param [in] block Control block to compile.
    * \param [out] container Container to fill with generated code.
    */
   void compileCreateBlock(const IR::ControlBlock *block, nlohmann::json &container);

   /**
    * \brief Compiles update control block.
    *
    * \param [in] block Control block to compile.
    * \param [out] container Container to fill with generated code.
    */
   void compileUpdateBlock(const IR::ControlBlock *block, nlohmann::json &container);
};

} // namespace exporter
#endif // _BACKENDS_P4E_CACHE_H_
