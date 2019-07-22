/**
 * \file exporter.h
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

#ifndef _BACKENDS_P4E_EXPORTER_H_
#define _BACKENDS_P4E_EXPORTER_H_

#include <vector>
#include <nlohmann/json.hpp>

#include "ir/ir.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#include "options.h"
#include "utils.h"

namespace exporter {

typedef struct {
   uint16_t enterpriseNumber_; /**< Enterprise Number */
   uint16_t elementID_; /**< Information Element ID */
   int32_t length_; /**< Element export length. -1 for variable*/
} template_field_t;

/**
 * Compiles expressions to exporter specific code.
 */
class ExporterExpressionHelper : public ConstructExpression
{
 public:
   ExporterExpressionHelper(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   bool preorder(const IR::Member *expr) override;
   bool preorder(const IR::PathExpression *expr) override;

  private:
   /**
    * \brief True when `flow` are found in expression (for example `flow.src_addr`).
    */
   bool flowFound_;
};

/**
 * Compiles code of exporter_init control block.
 */
class ExporterInitVisitor : public CodeBuilder, public UnsupportedStatementInspector
{
public:
   ExporterInitVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container);
   bool preorder(const IR::MethodCallStatement *s) override;
   bool preorder(const IR::MethodCallExpression *expr) override;
   bool preorder(const IR::BlockStatement *s) override;

   std::vector<int> getTemplateMapping() const;
   std::vector<std::vector<template_field_t>> getTemplateFields() const;

private:
   std::vector<int> templateMapping_; /**< Contains IDs of registered templates. */
   std::vector<std::vector<template_field_t>> templateFields_; /**< Contains elements of registered templates.
      Order of items corresponds to templateMapping_ vector. */

   /**
    * \brief Compiles call of register_template extern function.
    *
    * \param [in] args Arguments of function call.
    */
   void processRegisterTemplate(const IR::Vector<IR::Argument> *args);
   /**
    * \brief Compiles call of add_template_field extern function.
    *
    * \param [in] args Arguments of function call.
    */
   void processAddTemplateField(const IR::Vector<IR::Argument> *args);
};

/**
 * Compiles code of exporter_fill control block.
 */
class ExporterFillVisitor : public CodeBuilder, public UnsupportedStatementInspector
{
public:
   ExporterFillVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container,
      std::vector<int> templateMapping, std::vector<std::vector<template_field_t>> templateFields);
   bool preorder(const IR::MethodCallStatement *s) override;
   bool preorder(const IR::MethodCallExpression *expr) override;
   bool preorder(const IR::BlockStatement *s) override;
   bool preorder(const IR::AssignmentStatement *s) override;
   bool preorder(const IR::IfStatement *s) override;

private:
   std::vector<int> templateMapping_; /**< Contains IDs of registered templates. */
   std::vector<int> templateSize_; /**< Contains lengths of static fields in registered templates.
      Order of items corresponds to templateMapping_ vector. */
   std::vector<std::vector<template_field_t>> templateFields_; /**< Contains elements of registered templates.
      Order of items corresponds to templateMapping_ vector. */

   int currentTemplate_; /**< Index to templateMapping_ array. */
   int currentFillSize_; /**< Number of bytes filled in currently filled template. */
   int currentTemplateField_; /**< Index to templateFields_[n] array. */

   /**
    * \brief Compiles set_template extern function.
    *
    * \param [in] args Function call arguments.
    */
   void processSetTemplate(const IR::Vector<IR::Argument> *args);
   /**
    * \brief Compiles add_field extern function.
    *
    * \param [in] args Function call arguments.
    */
   void processAddField(const IR::Vector<IR::Argument> *args);
   /**
    * \brief Check if expressing is string. Used to distinguish fixed and varaible fields in add_field.
    *
    * \param [in] expr Tree node to check.
    * \return True if argument is string.
    */
   bool varIsString(const IR::Expression *expr);
};

/**
 * \brief Used to count total number of templates in exporter_init control block.
 */
class TemplateCountInspector : public Inspector
{
public:
   TemplateCountInspector(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   bool preorder(const IR::MethodCallExpression *expr) override;

   /**
    * \return Number of templates in control block.
    */
   uint32_t getCount() const;

private:
   P4::ReferenceMap *refMap_;
   P4::TypeMap *typeMap_;
   uint32_t count_; /**< Number of templates. */
};

/**
 * \brief Compiles exporter init and fill control blocks and generates source code files.
 */
class ExporterGenerator : public Generator
{
public:
   ExporterGenerator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap);

   /**
    * \brief Compiles code and generates source code files.
    */
   void generate();

private:
   nlohmann::json exporter_; /**< Container for generated C code. */
};

} // namespace exporter
#endif // _BACKENDS_P4E_EXPORTER_H_
